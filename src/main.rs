use clap::{Args, Parser, Subcommand};
mod keygen;

#[derive(Parser)]
#[command(author="Paul Côté", version, about, long_about=None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,    
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
    path_to_file: String
}

#[derive(Args)]
struct GetFileArgs {
    #[arg(required=true)]
    file_name: String
}

#[derive(Args)]
struct KeyGenArgs {
    #[arg(short='f', long="output-keyfile")]
    output_file: Option<String>
}

fn main() {
    let cli = Cli::parse();

    match &cli.command {
        Commands::SendFile(args) => println!("Sending file {}...", args.path_to_file),
        Commands::GetFile(args) => println!("Getting file {}...", args.file_name),
        Commands::KeyGen(args) => {
            println!("Generating public/private kyber1024 key pair.");
            let _ = keygen::generate_key_pair_files(args.output_file.clone());
        }
    }
}