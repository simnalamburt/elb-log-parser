use clap::{builder::ValueHint, Parser, ValueEnum};

#[derive(Parser)]
#[command(about, version, arg_required_else_help(true))]
pub struct Args {
    /// Type of load balancer.
    #[arg(value_enum, short, long, default_value_t = Type::Alb)]
    pub r#type: Type,

    #[command(flatten)]
    pub config: Config,

    /// Path of directory containing load balancer logs. To read from stdin, use "-".
    #[arg(value_hint = ValueHint::DirPath, allow_hyphen_values = true)]
    pub path: String,
}

#[derive(ValueEnum, Clone)]
pub enum Type {
    Alb,
    ClassicLb,
}

#[derive(Parser, Clone, Copy)]
pub struct Config {
    /// Skip parsing errors.
    #[arg(long)]
    pub skip_parse_errors: bool,
}
