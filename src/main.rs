use clap::{Args, Parser, Subcommand};

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
    GetFile(GetFileArgs)
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

fn main() {
    let cli = Cli::parse();

    match &cli.command {
        Commands::SendFile(args) => println!("Sending file {}...", args.path_to_file),
        Commands::GetFile(args) => println!("Getting file {}...", args.file_name)
    }
}