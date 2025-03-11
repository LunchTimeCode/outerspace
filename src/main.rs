use rocket::{Build, Rocket};

#[macro_use]
extern crate rocket;

mod authentication;
mod model;

#[launch]
async fn rocket() -> _ {
    let rocket = rocket::build();

    mount(rocket).await
}

async fn mount(rocket: Rocket<Build>) -> Rocket<Build> {
    rocket
        .mount("/", routes![authentication::get_me])
        .attach(authentication::fairing())
}
