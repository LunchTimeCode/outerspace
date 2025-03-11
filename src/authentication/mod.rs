use std::{
    collections::HashMap,
    env::{self, VarError},
};

use anyhow::anyhow;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, jwk::JwkSet};
use rocket::{
    Request, State,
    fairing::{AdHoc, Fairing},
    http::Status,
    log::private::warn,
    request::{FromRequest, Outcome},
    serde::json::Json,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use permissions::Permission;

use crate::model::read::{AdminUser, AuthorizedUser};

pub mod permissions;

pub fn fairing() -> impl Fairing {
    AdHoc::try_on_ignite("Load jwt decoding keys", |rocket| async {
        let keys = match (fetch_jwk_set().await, load_jwk_secret()) {
            (Ok(map), _) => Decoders::Multiple(map),
            (Err(_), Ok(decoder)) => {
                warn!("using single jwt key secret");
                Decoders::Single(decoder.into())
            }
            (Err(multiple_err), Err(single_err)) => {
                error!("Failed to fetch jwk key set: {multiple_err}");
                error!("Failed to fetch jwk secret: {single_err}");
                return Err(rocket);
            }
        };
        Ok(rocket.manage(keys))
    })
}

fn validation(algo: Algorithm) -> Validation {
    let mut validation = Validation::new(algo);
    let aud = env::var("AUTH_JWT_AUD");
    validation.set_audience(&[aud.as_deref().unwrap_or("outerspace.silenlocatelli.com")]);
    validation
        .required_spec_claims
        .insert("tax_platform_apps".into());
    validation
}

struct Decoder {
    key: DecodingKey,
    validation: Validation,
}

enum Decoders {
    Single(Box<Decoder>),
    Multiple(HashMap<String, Decoder>),
}

impl Decoder {
    fn decode(&self, token: &str) -> anyhow::Result<AccessToken> {
        Ok(jsonwebtoken::decode(token, &self.key, &self.validation)?.claims)
    }
}

impl Decoders {
    fn decode(&self, token: &str) -> anyhow::Result<AccessToken> {
        let header = jsonwebtoken::decode_header(token)?;
        let decoder: &Decoder = match self {
            Decoders::Single(decoder) => decoder,
            Decoders::Multiple(map) => header
                .kid
                .and_then(|k| map.get(&k))
                .ok_or_else(|| anyhow!("unknown token key"))?,
        };
        decoder.decode(token)
    }
}

fn load_jwk_secret() -> Result<Decoder, VarError> {
    let secret = env::var("AUTH_HS256_SECRET")?;
    let validation = validation(Algorithm::HS256);
    let key = DecodingKey::from_secret(secret.as_bytes());
    Ok(Decoder { key, validation })
}

async fn fetch_jwk_set() -> anyhow::Result<HashMap<String, Decoder>> {
    let url = env::var("AUTH_JWKS_URL")?;
    let key_set: JwkSet = reqwest::get(url).await?.json::<JwkSet>().await?;
    Ok(key_set
        .keys
        .into_iter()
        .filter_map(|jwk| {
            let key = DecodingKey::from_jwk(&jwk).ok()?;
            let validation = validation(Algorithm::RS256);
            let kid = jwk.common.key_id?;
            Some((kid, Decoder { key, validation }))
        })
        .collect())
}

#[allow(unused)]
#[derive(Debug, Deserialize)]
pub struct AccessToken {
    pub email: Option<String>,
    user_id: Uuid,
    #[serde(default)]
    permissions: Vec<Permission>,
}

#[async_trait]
impl<'r> FromRequest<'r> for AccessToken {
    type Error = anyhow::Error;
    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let Some(token) = request
            .headers()
            .get("authorization")
            .next()
            .and_then(|v| v.strip_prefix("Bearer "))
        else {
            return Outcome::Error((Status::Unauthorized, anyhow!("missing authorization token")));
        };
        let Outcome::Success(decoders) = request.guard::<&State<Decoders>>().await else {
            error!("no jwt decoding key found");
            return Outcome::Forward(Status::Ok);
        };
        match decoders.decode(token) {
            Ok(token) => Outcome::Success(token),
            Err(err) => {
                warn!("Invalid token: '{token}'");
                return Outcome::Error((Status::Unauthorized, err));
            }
        }
    }
}

#[async_trait]
impl<'r> FromRequest<'r> for AuthorizedUser {
    type Error = anyhow::Error;
    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let token = match request.guard::<AccessToken>().await {
            Outcome::Success(token) => token,
            Outcome::Error(err) => return Outcome::Error(err),
            Outcome::Forward(x) => return Outcome::Forward(x),
        };

        warn!("request user not found in database. Using JWT token content");
        let user = AuthorizedUser::create(token.user_id);

        match user {
            Ok(user) => Outcome::Success(user),
            Err(err) => Outcome::Error((Status::Forbidden, err)),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct MeUser {
    pub id: Uuid,
}

impl From<AuthorizedUser> for MeUser {
    fn from(value: AuthorizedUser) -> Self {
        Self { id: value.id }
    }
}

#[get("/users/me")]
pub fn get_me(req_user: AuthorizedUser) -> Json<MeUser> {
    Json(req_user.into())
}

#[async_trait]
impl<'r> FromRequest<'r> for AdminUser {
    type Error = anyhow::Error;
    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        match request.guard::<AccessToken>().await {
            Outcome::Success(token) => match token.to_admin() {
                Ok(user) => Outcome::Success(user),
                Err(_) => Outcome::Error((
                    Status::Forbidden,
                    anyhow!("you do not have enough permission"),
                )),
            },
            Outcome::Error(err) => Outcome::Error(err),
            Outcome::Forward(x) => Outcome::Forward(x),
        }
    }
}
