use uuid::Uuid;

use email_address::EmailAddress;
use thiserror::Error;

pub mod platform {
    use super::*;
    use serde::Serialize;
    use std::collections::HashSet;
    use uuid::Uuid;

    #[derive(Debug, Serialize)]
    pub struct User {
        pub id: Uuid,
        pub email: String,
        pub given_name: String,
        pub family_name: String,
        pub environments: HashSet<Environment>,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserInfo {
    pub email: EmailAddress,
    pub given_name: String,
    pub family_name: String,
}

impl Ord for UserInfo {
    fn cmp(&self, other: &Self) -> Ordering {
        self.family_name
            .cmp(&other.family_name)
            .then_with(|| self.given_name.cmp(&other.given_name))
            .then_with(|| self.email.as_str().cmp(other.email.as_str()))
    }
}

impl PartialOrd for UserInfo {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Environment {
    Prod,
    Test,
}

use serde::{Deserialize, Serialize};
use std::cmp::Ordering;

/// The authenticated admin user making the request.
#[derive(Debug, Copy, Clone)]
pub struct AdminUser;

/// The authenticated user making the request.
#[derive(Debug, Clone)]
pub struct AuthorizedUser {
    pub id: Uuid,
}

impl AuthorizedUser {
    pub fn create(id: Uuid) -> anyhow::Result<Self> {
        Ok(Self { id })
    }
}
#[derive(Debug, Clone, Error, Eq, PartialEq)]
#[error("You do not have sufficient permissions to perform this action")]
pub struct Forbidden;

#[derive(Debug, Clone, Error, Eq, PartialEq)]
#[error("User not found")]
pub struct UserDoesNotExist;

#[derive(Debug, Clone, Error, Eq, PartialEq)]
pub enum GrantAccessError {
    #[error("You do not have sufficient permissions to perform this action")]
    Forbidden,
}

impl From<Forbidden> for GrantAccessError {
    fn from(_: Forbidden) -> Self {
        Self::Forbidden
    }
}
