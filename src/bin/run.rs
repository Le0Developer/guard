use axum::serve;
use guard::{core::Core, db::setup_wizard, server::router::create_routers};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let core = Core::from_env().await?;
    setup_wizard(&mut core.db.clone()).await?;
    let (router, forwardauth) = create_routers(core);
    let address = std::env::var("LISTEN_ADDR").unwrap_or_else(|_| "0.0.0.0:4444".into());
    let forward_address =
        std::env::var("FORWARDAUTH_LISTEN_ADDR").unwrap_or_else(|_| "127.0.0.1:4445".into());
    let listener = tokio::net::TcpListener::bind(&address).await?;
    let forward_listener = tokio::net::TcpListener::bind(&forward_address).await?;
    println!("Guard listening on {}", listener.local_addr()?);
    println!(
        "ForwardAuth listening on {}",
        forward_listener.local_addr()?
    );
    tokio::try_join!(
        async {
            serve(
                listener,
                router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .await
        },
        async {
            serve(
                forward_listener,
                forwardauth.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .await
        }
    )?;
    Ok(())
}
