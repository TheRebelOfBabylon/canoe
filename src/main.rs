use clap::{Args, Parser, Subcommand};

#[derive(Parser)]
#[command(author="Paul Côté", version, about, long_about=None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    #[arg(short, long, default_value_t = 1)]
    count: u8,
}

#[derive(Subcommand)]
enum Commands {
    #[command(about="Adds two numbers")]
    Add(AddArgs)
}

#[derive(Args)]
struct AddArgs {
    first_number: i16,
    second_number: i16
}

fn main() {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Add(args) => println!("{} + {} = {}", args.first_number, args.second_number, args.first_number+args.second_number)
    }
}