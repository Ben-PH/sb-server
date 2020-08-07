use std::num::NonZeroU32;

use actix_files::{Files, NamedFile};
use actix_identity::{CookieIdentityPolicy, Identity, IdentityService};
use actix_web::{
    delete, get, middleware, post, web, App, HttpResponse, HttpServer, Responder, Result,
};
use rand::Rng;
use ring::rand::{SecureRandom, SystemRandom};

use mongodb::bson::{self, doc, spec, Binary};
use serde::{Deserialize, Serialize};

static PBKDF2_ALG: ring::pbkdf2::Algorithm = ring::pbkdf2::PBKDF2_HMAC_SHA256;
const CREDENTIAL_LEN: usize = ring::digest::SHA256_OUTPUT_LEN;
const VER_ITER: u32 = 1000;
#[derive(Serialize)]
pub struct Credential([u8; CREDENTIAL_LEN]);
// static PWD_DB_SALT: &[u8; 16] = b"database spicey!";

struct DbCollections {
    users: mongodb::Collection,
}

struct PwdDb {
    pbkdf2_iters: NonZeroU32,
    // TODO? include a db-wide salt
    storage: mongodb::Collection,
}

#[derive(Debug, Serialize, Deserialize)]
struct AuthData {
    email: String,
    password: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct UserDocument {
    _id: bson::oid::ObjectId,
    first_name: String,
    last_name: String,
    email: String,
    password: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct User {
    first_name: String,
    last_name: String,
    email: String,
    password: String,
}

async fn index(id: Identity) -> Result<NamedFile> {
    println!("your id is {:?}", id.identity());
    Ok(NamedFile::open("./client/index.html")?)
}

impl PwdDb {
    /// See [this stack-overflow](https://stackoverflow.com/a/674931) question on salting
    fn fill_salt(
        &self,
        rng: &SystemRandom,
        barray: &mut [u8],
    ) -> Result<(), ring::error::Unspecified> {
        rng.fill(barray)
    }
}

#[post("/create")]
async fn create(
    auth_data: web::Json<User>,
    app_data: web::Data<AppData>,
    user_db: web::Data<DbCollections>,
    pswd_db: web::Data<PwdDb>,
) -> Result<impl Responder> {
    let user_db = user_db.into_inner();
    let auth_data = auth_data.into_inner();
    if let Ok(Some(_)) = user_db
        .users
        .find_one(doc! {"email": &auth_data.email}, None)
        .await
    {
        return HttpResponse::Unauthorized()
            .reason("email already exists")
            .await;
    }

    // TODO CRUCIAL do these the rusty way. if it returned Err, we still go ahead :(
    let pswd_db = pswd_db.into_inner();
    if let Ok(Some(_)) = pswd_db
        .storage
        .find_one(doc! {"email": &auth_data.email}, None)
        .await
    {
        return HttpResponse::InternalServerError()
            .reason("inconsistent database")
            .await;
    }

    let mut salt = [0u8; CREDENTIAL_LEN];
    if pswd_db
        .fill_salt(&app_data.into_inner().rng, &mut salt)
        .is_err()
    {
        return HttpResponse::InternalServerError().await;
    }
    let mut to_store = Credential([0u8; CREDENTIAL_LEN]);
    ring::pbkdf2::derive(
        PBKDF2_ALG,
        pswd_db.pbkdf2_iters,
        &salt,
        &auth_data.password.as_bytes(),
        &mut to_store.0,
    );
    let hash = Binary {
        subtype: spec::BinarySubtype::Generic,
        bytes: to_store.0.to_vec(),
    };

    // TODO handle bad insertion
    pswd_db
        .storage
        .insert_one(
            doc! {
                "email": &auth_data.email,
                "hashed": &hash,
            },
            None,
        )
        .await;

    // TODO handle bad insertion
    user_db
        .users
        .insert_one(
            doc!{
                "first_name": auth_data.first_name,
                "last_name": auth_data.last_name,
                "email": auth_data.email,
                // TODO: link to password hashing document
                "salt": bson::Binary{subtype: bson::spec::BinarySubtype::Generic, bytes: salt.to_vec()}
            },
            None
        ).await;
    HttpResponse::Ok().await
}

#[post("/login")]
async fn login(
    id: Identity,
    auth_data: web::Json<AuthData>,
    passwords: web::Data<PwdDb>,
    col: web::Data<DbCollections>,
) -> Result<impl Responder> {
    let auth = auth_data.into_inner();
    let pwds = passwords.into_inner();
    let col = col.into_inner();
    let hash = match pwds
        .storage
        .find_one(doc! {"email": &auth.email}, None)
        .await
    {
        Ok(Some(mut doc)) => match doc.remove("hashed") {
            Some(bson::Bson::Binary(bin)) => {
                println!("{:#?}", doc);
                Some(bin.bytes)
            }

            _ => None,
        },
        _ => None,
    };

    let salt = match col.users.find_one(doc! {"email": &auth.email}, None).await {
        Ok(Some(mut doc)) => match doc.remove("salt") {
            Some(bson::Bson::Binary(bin)) => {
                println!("{:?}", doc);
                Some(bin.bytes)
            }

            _ => None,
        },
        _ => None,
    };

    // println!("{:?}", salt);
    // println!("{:?}", hash);

    // pull out the password hash and users salt from the database
    // TODO don't do unwrap in a scop guarded by is_some(). do it the rusty way.
    if salt.is_some()
        && hash.is_some()
        && ring::pbkdf2::verify(
            PBKDF2_ALG,
            pwds.pbkdf2_iters,
            salt.unwrap().as_slice(),
            auth.password.as_bytes(),
            hash.unwrap().as_slice(),
        )
        .is_ok()
    {
        id.remember(auth.email);
        HttpResponse::Ok().reason("you are logged in").json(user).await
    } else {
        HttpResponse::Unauthorized()
            .reason("invalid username or password")
            .await
    }
}

#[delete("")]
async fn logout(id: Identity) -> Result<impl Responder> {
    match id.identity() {
        Some(email) => {
            println!("goodbye, {:?}", email);
            id.forget();
            HttpResponse::Ok().finish().await
        }
        None => {
            println!("sorry, who are you?");
            HttpResponse::Unauthorized()
                .reason("invalid Authorization cookie")
                .await
        }
    }
}

struct AppData {
    rng: SystemRandom,
}

#[get("")]
async fn profile(id: Identity) -> Result<impl Responder> {
    match id.identity() {
        Some(_) => HttpResponse::Ok().await,
        None => HttpResponse::Unauthorized().await,
    }
}

#[actix_rt::main]
async fn main() -> std::io::Result<()> {
    std::env::set_var("RUST_LOG", "actix_web=info");
    env_logger::init();
    let db = mongodb::Client::with_uri_str("mongodb://localhost:27017")
        .await
        .unwrap()
        .database("spacebook");

    HttpServer::new(move || {
        // First fill is high-latency. so do it one time round
        let rng = ring::rand::SystemRandom::new();
        {
            let mut tmp_var = [0u8; 16];
            if let Err(e) = rng.fill(&mut tmp_var) {
                eprintln!("rng initialization fill() error: {:?}", e);
            }
        }
        let private_key = rand::thread_rng().gen::<[u8; 32]>();
        let users = db.collection("users");
        let pwds = db.collection("passwords");

        App::new()
            .wrap(IdentityService::new(
                CookieIdentityPolicy::new(&private_key)
                    .name("Authorization")
                    .max_age(60 * 10)
                    .secure(true),
            ))
            .wrap(middleware::Logger::default())
            .data(DbCollections { users })
            .data(PwdDb {
                pbkdf2_iters: NonZeroU32::new(VER_ITER).unwrap(),
                storage: pwds,
            })
            .data(AppData { rng })
            .service(
                web::scope("/api/auth")
                    .service(create)
                    .service(profile)
                    .service(login)
                    .service(logout)
                    .default_service(web::route().to(web::HttpResponse::NotFound)),
            )
            .service(Files::new("/pkg", "./client/pkg"))
            .default_service(web::get().to(index))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
