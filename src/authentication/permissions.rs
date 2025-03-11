use crate::authentication::AccessToken;
use crate::model::read::AdminUser;
use rocket::http::Status;
use serde::Deserialize;

#[derive(PartialEq, Eq, Debug)]
pub struct InsufficientScope(String);

impl From<InsufficientScope> for Status {
    fn from(_: InsufficientScope) -> Self {
        Status::Forbidden
    }
}

impl From<anyhow::Error> for InsufficientScope {
    fn from(value: anyhow::Error) -> Self {
        Self(value.to_string())
    }
}

impl AccessToken {
    pub fn require_permission(
        &self,
        expected_scope: Permission,
    ) -> Result<&Self, InsufficientScope> {
        if self
            .permissions
            .iter()
            .copied()
            .any(|scope| scope == expected_scope)
        {
            Ok(self)
        } else {
            Err(InsufficientScope(format!(
                "user has only: {allowed_scope:?}",
                allowed_scope = self.permissions
            )))
        }
    }

    pub fn to_admin(&self) -> Result<AdminUser, InsufficientScope> {
        self.require_permission(Permission::Admin)
            .map(|_| AdminUser)
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Deserialize)]
pub enum Permission {
    #[serde(rename = "admin")]
    Admin,
}
