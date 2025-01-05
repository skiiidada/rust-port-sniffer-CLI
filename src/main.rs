use bpaf::Bpaf; // Import the `bpaf` crate for command-line argument parsing.
use std::io::{self, Write}; // Import I/O operations for writing to stdout.
use std::net::{IpAddr, Ipv4Addr}; // Import IP address types for network operations.
use std::sync::mpsc::{channel, Sender}; // Import multi-producer, single-consumer channels for inter-thread communication.
use tokio::net::TcpStream; // Import the asynchronous `TcpStream` for networking.
use tokio::task; // Import `tokio::task` to spawn asynchronous tasks.

// Define the maximum port number (65535).
const MAX: u16 = 65535;

// Define a fallback IP address for cases where none is provided by the user.
const IPFALLBACK: IpAddr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

// Structure to hold command-line arguments.
#[derive(Debug, Clone, Bpaf)] // Derive debugging and cloning traits for this structure and enable `bpaf` processing.
#[bpaf(options)] // Mark this struct as being used for `bpaf` options parsing.
pub struct Arguments {
    // Address argument with short and long flags (-a, --address). Falls back to `IPFALLBACK` if not provided.
    #[bpaf(long, short, argument("Address"), fallback(IPFALLBACK))]
    /// The address that you want to sniff. Must be a valid IPv4 address. Falls back to 127.0.0.1.
    pub address: IpAddr,

    // Start port argument with short and long flags (-s, --start). Must be greater than 0.
    #[bpaf(
        long("start"),
        short('s'),
        guard(start_port_guard, "Must be greater than 0"),
        fallback(1u16)
    )]
    /// The start port for the sniffer. (must be greater than 0)
    pub start_port: u16,

    // End port argument with short and long flags (-e, --end). Must be less than or equal to 65535.
    #[bpaf(
        long("end"),
        short('e'),
        guard(end_port_guard, "Must be less than or equal to 65535"),
        fallback(MAX)
    )]
    /// The end port for the sniffer. (must be less than or equal to 65535)
    pub end_port: u16,
}

// Guard function to ensure the start port is greater than 0.
fn start_port_guard(input: &u16) -> bool {
    *input > 0
}

// Guard function to ensure the end port is less than or equal to MAX (65535).
fn end_port_guard(input: &u16) -> bool {
    *input <= MAX
}

// Function to scan a specific port.
async fn scan(tx: Sender<u16>, start_port: u16, addr: IpAddr) {
    // Attempt to connect to the given IP address and port.
    match TcpStream::connect(format!("{}:{}", addr, start_port)).await {
        // If the connection is successful:
        Ok(_) => {
            print!("."); // Print a dot to indicate progress.
            io::stdout().flush().unwrap(); // Flush stdout to ensure the dot appears immediately.
            tx.send(start_port).unwrap(); // Send the port number to the channel.
        }
        // If the connection fails (port is closed):
        Err(_) => {}
    }
}

// Entry point of the program.
#[tokio::main] // Use the `tokio` runtime for asynchronous execution.
async fn main() {
    // Parse the command-line arguments.
    let opts = arguments().run();

    // Initialize a channel for inter-task communication.
    let (tx, rx) = channel();

    // Iterate over the range of ports specified by the user.
    for i in opts.start_port..opts.end_port {
        let tx = tx.clone(); // Clone the transmitter for each task.

        // Spawn an asynchronous task to scan the current port.
        task::spawn(async move { scan(tx, i, opts.address).await });
    }

    // Create a vector to store open ports.
    let mut out = vec![];

    // Drop the original transmitter to signal completion to the receiver.
    drop(tx);

    // Collect all open ports from the receiver and add them to the vector.
    for p in rx {
        out.push(p);
    }

    println!(""); // Print a newline for output formatting.

    // Sort the vector of open ports in ascending order.
    out.sort();

    // Print each open port.
    for v in out {
        println!("{} is open", v); // Display the open port.
    }
}
