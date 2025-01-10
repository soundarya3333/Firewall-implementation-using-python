import socket
import random
import string

def generate_random_packet(size=1024):
    """Generates a random packet with specified size."""
    return ''.join(random.choices(string.ascii_letters + string.digits, k=size)).encode()

def get_sender_ip(dest_ip):
    """Determine the sender IP address based on the destination IP."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as temp_sock:
        # Use a dummy connection to find out the IP address used for this destination
        temp_sock.connect((dest_ip, 8080))
        sender_ip = temp_sock.getsockname()[0]
    return sender_ip

def main():
    try:
        # Ask for destination IP address only
        dest_ip = input("Enter the destination IP address: ")
        dest_port = 8080  # Default port

        # Validate IP address
        if not dest_ip:
            print("Invalid IP address.")
            return

        # Ask for the number of packets to send
        num_packets = int(input("Enter the number of packets to send: "))
        if num_packets <= 0:
            print("The number of packets should be a positive integer.")
            return

        # Determine the sender's IP address
        sender_ip = get_sender_ip(dest_ip)

        # Set up the UDP socket
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            print(f"Sending {num_packets} packets to {dest_ip}:{dest_port} from {sender_ip}...")

            for i in range(num_packets):
                # Generate a random packet
                packet = generate_random_packet()

                # Send packet to the specified destination
                sock.sendto(packet, (dest_ip, dest_port))
                print(f"Sent packet {i + 1} to {dest_ip}:{dest_port}")

        # Print the sender's IP address after sending the packets
        print(f"Packet sending completed. Packets were sent from IP address: {sender_ip}")

    except KeyboardInterrupt:
        print("\nPacket sending stopped.")
    except ValueError:
        print("Please enter a valid number for the packets.")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()
