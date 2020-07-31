use actix::{prelude::*};
use actix_files::{Files, NamedFile};
use actix_identity::Identity;
use actix_identity::{CookieIdentityPolicy, IdentityService};
use actix_multipart::Multipart;
use actix_web::{get, post, web, App, HttpResponse, HttpServer, Result, Responder};
use futures::stream::StreamExt;
use rand::Rng;


async fn index(id: Identity) -> Result<NamedFile> {
    println!("your id is {:?}", id.identity());
    Ok(NamedFile::open("./client/index.html")?)
}


#[post("/login/{name}")]
async fn login(id: Identity, name: web::Path<String>) -> Result<impl Responder> {

    id.remember(name.to_string());
    println!("hello, {:?}", name);
    HttpResponse::Ok().finish().await
}

#[post("/logout/{name}")]
async fn logout(id: Identity, name: web::Path<String>) -> Result<impl Responder> {

    match id.identity() {
        Some(name) => {
            println!("goodbye, {:?}", name);
            id.forget();
            HttpResponse::Ok().finish().await
        },
        None => {
            println!("you say you are {:?}, but I don't think we've met :(", name);
            HttpResponse::Ok().finish().await
        }

    }

}
#[actix_rt::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(move || {
        let private_key = rand::thread_rng().gen::<[u8; 32]>();
        App::new()
            .wrap(IdentityService::new(
                CookieIdentityPolicy::new(&private_key)
                    .name("auth")
                    .secure(false),
            ))
            .service(
                web::scope("/api/")
                     .service(login)
                     .service(logout)
                     .service(Files::new("/pkg", "./client/pkg"))
                    .default_service(web::route().to(web::HttpResponse::NotFound)),
            )
            .service(Files::new("/pkg", "./client/pkg"))
            .default_service(web::get().to(index))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
