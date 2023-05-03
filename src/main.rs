use clap::{Args, Parser, Subcommand};
mod client;
mod keygen;

#[derive(Parser)]
#[command(author="Paul Côté", version, about, long_about=None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,    
    #[arg(short='i', long="identity-file")]
    path_to_key: Option<String>
}

#[derive(Subcommand)]
enum Commands {
    #[command(about="send a file")]
    SendFile(SendFileArgs),
    #[command(about="get a file")]
    GetFile(GetFileArgs),
    #[command(name="keygen", about="generate a public/private key pair")]
    KeyGen(KeyGenArgs)
}

#[derive(Args)]
struct SendFileArgs {
    #[arg(required=true)]
    path_to_file: String,
    remote_address: String,
    #[arg(required=true, short='p', long="public-key")]
    public_key_file: String,
}

#[derive(Args)]
struct GetFileArgs {
    #[arg(required=true)]
    file_name: String,
    remote_address: String,
    #[arg(required=true, short='p', long="public-key")]
    public_key_file: String,
}

#[derive(Args)]
struct KeyGenArgs {
    #[arg(short='f', long="output-keyfile")]
    output_file: Option<String>
}

fn main() {
    let cli = Cli::parse();
    match &cli.command {
        Commands::SendFile(args) => {
            println!("Sending file {}...", args.path_to_file);
            let sk = client::import_identity_file(cli.path_to_key);
            println!("Secret Key {:?}", sk);
        },
        Commands::GetFile(args) => println!("Getting file {}...", args.file_name),
        Commands::KeyGen(args) => {
            println!("Generating public/private kyber1024 key pair.");
            let _ = keygen::generate_key_pair_files(args.output_file.clone());
        }
    }
}