import random
import time
import json
import csv
import matplotlib.pyplot as plt
import pandas as pd
import smtplib
from email.mime.text import MIMEText
from datetime import datetime

class OTPGenerator:
    def __init__(self, length=6, expiry_seconds=30):
        self.length = length
        self.expiry_seconds = expiry_seconds
        self.generated_otps = []

    def generate_otp(self):
        digits = "0123456789"
        otp = "".join(random.choice(digits) for _ in range(self.length))
        expiry_time = time.time() + self.expiry_seconds
        temp_password = self.generate_temp_password()
        
        otp_data = {
            "otp": otp,
            "expiry_time": expiry_time,
            "temp_password": temp_password,
            "generation_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        self.generated_otps.append(otp_data)
        
        return otp, expiry_time, temp_password

    def generate_temp_password(self, length=8):
        chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"
        return "".join(random.choice(chars) for _ in range(length))

    def save_otps_to_file(self, filename="otp_log.json"):
        try:
            with open(filename, 'w') as file:
                json.dump(self.generated_otps, file, indent=4)
            print(f"✅ OTP data saved to {filename}")
        except Exception as e:
            print(f"❌ Error saving OTPs to file: {e}")

    def export_otps_to_csv(self, filename="otp_analysis.csv"):
        try:
            with open(filename, 'w', newline='') as file:
                writer = csv.writer(file)
                writer.writerow(['OTP', 'Temp Password', 'Generation Time'])
                for otp_data in self.generated_otps:
                    writer.writerow([
                        otp_data['otp'],
                        otp_data['temp_password'],
                        otp_data['generation_time']
                    ])
            print(f"✅ OTP analysis exported to {filename}")
        except Exception as e:
            print(f"❌ Error exporting to CSV: {e}")

class OTPValidator:
    def __init__(self):
        self.all_validation_attempts = [] 

    def validate(self, otp, expiry_time, user_input):
        current_time = time.time()
        attempt_data = {
            "attempt_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "user_input": user_input,
            "valid": False,
            "message": ""
        }

        try:
            if not user_input.isdigit():
                raise ValueError("Invalid code. Must contain numbers only.")
            
            if len(user_input) != len(otp):
                raise ValueError(f"Code must be exactly {len(otp)} digits long.")
            
            if current_time > expiry_time:
                raise Exception("OTP has expired.")
            
            if user_input == otp:
                attempt_data["valid"] = True
                attempt_data["message"] = "✅ OTP is correct!"
                self.all_validation_attempts.append(attempt_data)
                return True, attempt_data["message"]
            else:
                raise Exception("OTP is incorrect.")
                
        except ValueError as ve:
            attempt_data["message"] = f"⚠️ {ve}"
            self.all_validation_attempts.append(attempt_data)
            return False, attempt_data["message"]
        except Exception as e:
            attempt_data["message"] = f"❌ {e}"
            self.all_validation_attempts.append(attempt_data)
            return False, attempt_data["message"]

    def save_validation_log(self, filename="validation_log.csv"):
        try:
            with open(filename, 'w', newline='', encoding='utf-8') as file:
                writer = csv.writer(file)
                writer.writerow(['Timestamp', 'Input', 'Valid', 'Message'])
                
                for attempt in self.all_validation_attempts:
                    writer.writerow([
                        attempt["attempt_time"],
                        attempt["user_input"],
                        attempt["valid"],
                        attempt["message"]
                    ])
            print(f"✅ Validation log saved to {filename}")
        except Exception as e:
            print(f"❌ Error saving validation log: {e}")

    def generate_validation_report(self):
        if not self.all_validation_attempts:
            print("No validation attempts to report.")
            return
            
        valid_count = sum(1 for attempt in self.all_validation_attempts if attempt["valid"])
        invalid_count = len(self.all_validation_attempts) - valid_count
        
        print("\n" + "="*50)
        print("VALIDATION REPORT")
        print("="*50)
        print(f"Total attempts: {len(self.all_validation_attempts)}")
        print(f"Successful validations: {valid_count}")
        print(f"Failed validations: {invalid_count}")
        print(f"Success rate: {(valid_count/len(self.all_validation_attempts))*100:.2f}%")
        print("="*50)

class EmailService:
    def __init__(self):
        self.smtp_server = "smtp.gmail.com"
        self.smtp_port = 587
        self.sender_email = "your_email@gmail.com"  
        self.sender_password = "your_app_password"  

    def send_otp_email(self, recipient_email, otp, expiry_minutes=0.5):
        """Send OTP code to the specified email"""
        try:
            # If email is not configured, show simulation message
            if self.sender_email == "your_email@gmail.com":
                print(f"\n📧 [Simulation] Code {otp} sent to {recipient_email}")
                print("⚠️ To use real email, please configure email settings in the code")
                return True, "✅ Code sent (simulation)"
            
            subject = "Your Verification Code"
            body = f"""
            Your verification code: {otp}
            Valid for: {expiry_minutes} minutes
            
            Please do not share this code with anyone.
            
            This is an automated message from the OTP management system.
            """
            
            msg = MIMEText(body, 'plain', 'utf-8')
            msg['Subject'] = subject
            msg['From'] = self.sender_email
            msg['To'] = recipient_email
            
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(self.sender_email, self.sender_password)
                server.send_message(msg)
            
            return True, "✅ Code sent to your email"
        except Exception as e:
            return False, f"❌ Failed to send email: {e}"

class VisualizationEngine:
    def plot_validation_stats(self, validation_log_file="validation_log.csv"):
        try:
            df = pd.read_csv(validation_log_file)
            df['Timestamp'] = pd.to_datetime(df['Timestamp'])
            df['Hour'] = df['Timestamp'].dt.hour
            
            fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))
            
            success_count = df['Valid'].sum()
            failure_count = len(df) - success_count
            ax1.pie([success_count, failure_count], 
                   labels=['Success', 'Failure'],
                   autopct='%1.1f%%',
                   colors=['#4CAF50', '#F44336'])
            ax1.set_title('OTP Validation Results')
            
            hourly_attempts = df['Hour'].value_counts().sort_index()
            ax2.bar(hourly_attempts.index, hourly_attempts.values)
            ax2.set_xlabel('Hour of Day')
            ax2.set_ylabel('Number of Attempts')
            ax2.set_title('Validation Attempts by Hour')
            ax2.set_xticks(range(0, 24, 2))
            
            plt.tight_layout()
            plt.savefig('validation_stats.png')
            print("✅ Validation statistics chart saved as 'validation_stats.png'")
            
        except Exception as e:
            print(f"❌ Error generating visualization: {e}")

class OTPManager:
    def __init__(self, max_attempts=3, block_seconds=30):
        self.generator = OTPGenerator()
        self.validator = OTPValidator()
        self.email_service = EmailService()
        self.visualization_engine = VisualizationEngine()
        
        self.max_attempts = max_attempts
        self.block_seconds = block_seconds
        self.attempts = 0
        self.otp, self.expiry_time, self.temp_password = self.generator.generate_otp()

    def reset_otp(self):
        self.otp, self.expiry_time, self.temp_password = self.generator.generate_otp()
        print(f"🔑 New OTP: {self.otp} (valid for {self.generator.expiry_seconds} seconds)")
        print(f"🔐 Temporary password: {self.temp_password}")

    def load_users_from_file(self, filename="users.csv"):
        users = []
        try:
            with open(filename, 'r', encoding='utf-8') as file:
                reader = csv.reader(file)
                next(reader)  # Skip header
                for row in reader:
                    if len(row) >= 2:
                        users.append({"name": row[0], "email": row[1]})
            print(f"✅ Loaded {len(users)} users from {filename}")
        except FileNotFoundError:
            print("⚠️ Users file not found. Creating a new one.")
            # Create new file if it doesn't exist
            with open(filename, 'w', newline='', encoding='utf-8') as file:
                writer = csv.writer(file)
                writer.writerow(["Name", "Email"])
            print("✅ Created new users.csv file")
        except Exception as e:
            print(f"❌ Error reading users file: {e}")
        return users

    def add_user_to_file(self, name, email, filename="users.csv"):
        """Add a new user to the users file"""
        try:
            with open(filename, 'a', newline='', encoding='utf-8') as file:
                writer = csv.writer(file)
                writer.writerow([name, email])
            print(f"✅ User {name} added to {filename}")
            return True
        except Exception as e:
            print(f"❌ Error adding user to file: {e}")
            return False

    def generate_reports(self):
        print("\n📊 Generating system reports...")
        self.generator.export_otps_to_csv()
        self.validator.generate_validation_report()
        self.visualization_engine.plot_validation_stats()

    def run(self):
        print("=" * 60)
        print("           OTP MANAGEMENT SYSTEM")
        print("=" * 60)
        print("🔒 Cybersecurity Python Project")
        print("📧 Email Integration")
        print("=" * 60)
        
        while True:
            print("\nOptions:")
            print("1. Run OTP Validation")
            print("2. Generate Reports & Visualizations")
            print("3. Exit")
            
            choice = input("Select an option (1-3): ").strip()
            
            if choice == "1":
                self.run_otp_validation()
            elif choice == "2":
                self.generate_reports()
            elif choice == "3":
                print("👋 Exiting system. Goodbye!")
                break
            else:
                print("❌ Invalid option. Please try again.")

    def run_otp_validation(self):
        users = self.load_users_from_file()
        recipient_email = None
        
        # Select or add user
        if users:
            print("👥 Registered users:")
            for i, user in enumerate(users, 1):
                print(f"{i}. {user['name']} - {user['email']}")
            
            print(f"{len(users)+1}. Add new user")
            
            user_input = input("Select user number or add new user: ").strip()
            
            # Check if input is a direct email
            if "@" in user_input and "." in user_input:
                recipient_email = user_input
                print(f"📧 Using direct email: {recipient_email}")
            else:
                try:
                    choice = int(user_input)
                    
                    if 1 <= choice <= len(users):
                        selected_user = users[choice-1]
                        recipient_email = selected_user["email"]
                        print(f"📧 Selected: {selected_user['name']} - {recipient_email}")
                        
                    elif choice == len(users)+1:
                        # Add new user
                        name = input("Enter user name: ").strip()
                        email = input("Enter user email: ").strip()
                        
                        if name and email:
                            if self.add_user_to_file(name, email):
                                recipient_email = email
                                print(f"📧 New user added: {name} - {email}")
                            else:
                                print("❌ Failed to add user. Using default mode.")
                        else:
                            print("❌ Invalid name or email. Using default mode.")
                    else:
                        print("⚠️ Invalid choice. Using default mode.")
                        
                except ValueError:
                    print("⚠️ Invalid input. Using default mode.")
        
        # If no users or no user selected, ask for email
        if not recipient_email:
            email_input = input("Enter email to send OTP (or press Enter to skip): ").strip()
            if email_input:
                if "@" in email_input and "." in email_input:
                    recipient_email = email_input
                    print(f"📧 OTP will be sent to: {recipient_email}")
                else:
                    print("❌ Invalid email format. OTP will not be sent.")
            else:
                print("⚠️ No email provided. OTP will not be sent.")
        
        # Send code via email if available
        if recipient_email:
            success, message = self.email_service.send_otp_email(recipient_email, self.otp)
            print(message)
        
        print(f"🔑 Your OTP: {self.otp} (valid for {self.generator.expiry_seconds} seconds)")
        print(f"🔐 Temporary password: {self.temp_password}")

        while True:
            try:
                user_input = input("➡️ Enter OTP: ")
                valid, message = self.validator.validate(self.otp, self.expiry_time, user_input)
                print(message)

                if valid:
                    print("🎉 Verification successful. Access granted.")
                    self.generator.save_otps_to_file()
                    self.validator.save_validation_log()
                    
                    # After successful verification, return to main menu
                    print("\nReturning to main menu...")
                    break
                elif "expired" in message.lower():
                    print("🔄 OTP expired. Generating new code...")
                    self.reset_otp()
                    self.attempts = 0
                else:
                    self.attempts += 1
                    if self.attempts >= self.max_attempts:
                        print(f"⛔ Too many failed attempts. Blocked for {self.block_seconds} seconds...")
                        time.sleep(self.block_seconds)
                        print("🔓 Block lifted.")
                        self.reset_otp()
                        self.attempts = 0
                    else:
                        print(f"🔄 Wrong attempt ({self.attempts}/{self.max_attempts}). Generating new code...")
                        self.reset_otp()
            
            except KeyboardInterrupt:
                print("\n❌ Operation cancelled by user.")
                break
            except Exception as e:
                print(f"❌ An unexpected error occurred: {e}")
                self.generator.save_otps_to_file()
                self.validator.save_validation_log()

def create_sample_files():
    try:
        with open("users.csv", 'x', newline='', encoding='utf-8') as file:
            writer = csv.writer(file)
            writer.writerow(["Name", "Email"])
            writer.writerow(["Ahmed Mohamed", "ahmed@example.com"])
            writer.writerow(["Sara Abdullah", "sara@example.com"])
        print("✅ Created users.csv file")
    except FileExistsError:
        print("⚠️ users.csv file already exists")
    
if __name__ == "__main__":
    create_sample_files()
    
    manager = OTPManager()
    
    try:
        manager.run()
    except Exception as e:
        print(f"❌ Fatal error: {e}")
    finally:
        manager.generator.save_otps_to_file()
        manager.validator.save_validation_log()