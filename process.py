import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from collections import Counter
import re
from scipy import stats
from tqdm import tqdm
import logging
from sklearn.linear_model import LinearRegression
import hashlib
import os
import subprocess

def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[
            logging.FileHandler("password_analysis.log"),
            logging.StreamHandler()
        ]
    )

def load_dictionary(file_path="/usr/share/dict/words"):
    """Loads a dictionary of words from a specified file."""
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return set(line.strip().lower() for line in f)
    except FileNotFoundError:
        logging.error(f"Dictionary file not found at {file_path}. Please ensure the file exists.")
        return set()

def check_predictable(passwords, dictionary_words):
    """Checks if passwords exist in the dictionary."""
    predictable = []
    for pwd in passwords:
        if pwd.lower() in dictionary_words:
            predictable.append(pwd)
    return predictable

def check_rainbow_table(passwords, rainbow_directory="rainbow"):
    """Checks passwords against precomputed hashes in the rainbow directory."""
    cracked_passwords = {}
    try:
        rainbow_files = [os.path.join(rainbow_directory, file_name) for file_name in os.listdir(rainbow_directory) if os.path.isfile(os.path.join(rainbow_directory, file_name))]
        for file_path in tqdm(rainbow_files, desc="Processing Rainbow Files"):
            with open(file_path, "rb") as rainbow_file:  # Open in binary mode
                precomputed_hashes = set(line.strip() for line in rainbow_file)
                for pwd in passwords:
                    ntlm_hash = hashlib.new('md4', pwd.encode('utf-16le')).hexdigest().upper().encode('utf-8')  # Encode hash to binary
                    if ntlm_hash in precomputed_hashes:
                        cracked_passwords[pwd] = os.path.basename(file_path)  # Store the file (table) that cracked it
    except FileNotFoundError:
        logging.error(f"Rainbow directory '{rainbow_directory}' not found.")
    except Exception as e:
        logging.error(f"Error processing rainbow table files: {e}")
    return cracked_passwords


def strength_check(password):
    """Determine if a password is strong, medium, or weak based on length and composition."""
    if len(password) < 8:
        return "Weak"
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(not c.isalnum() for c in password)
    if has_upper and has_lower and has_digit and has_special:
        return "Strong"
    if (has_upper or has_lower) and (has_digit or has_special):
        return "Medium"
    return "Weak"

def analyze_passwords(passwords):
    """
    Analyzes a cleaned list of passwords for various metrics including length, character composition,
    trends, and security weaknesses.

    Parameters:
        passwords (list of str): List of cleaned passwords.

    Outputs insights and visualizations for each analysis step.
    """
    logging.info("Starting password analysis...")

    # Load dictionary words
    logging.info("Loading dictionary words...")
    dictionary_words = load_dictionary()

    # Open the results file
    with open("password_calculated_values.txt", "w") as results_file:

        # 2. Analyze Password Length
        logging.info("Analyzing password lengths...")
        lengths = [len(pwd) for pwd in passwords]

        # Exclude outliers for better readability in graphs
        q1 = np.percentile(lengths, 25)
        q3 = np.percentile(lengths, 75)
        iqr = q3 - q1
        lower_bound = max(0, q1 - 1.5 * iqr)
        upper_bound = q3 + 1.5 * iqr
        filtered_lengths = [l for l in lengths if lower_bound <= l <= upper_bound]
        
        results_file.write("Password Length Analysis:\n")
        results_file.write(f"Mean length: {np.mean(lengths):.2f}\n")
        results_file.write(f"Median length: {np.median(lengths):.2f}\n")
        
        # Corrected mode calculation
        mode_result = stats.mode(lengths, keepdims=True)
        results_file.write(f"Mode length: {mode_result.mode[0]} (appears {mode_result.count[0]} times)\n")
        
        results_file.write(f"Standard deviation: {np.std(lengths):.2f}\n")
        results_file.write(f"Passwords ≥8 characters: {len([l for l in lengths if l >= 8])}/{len(lengths)}\n")

        # Histogram of password lengths
        logging.info("Creating histogram of password lengths...")
        plt.hist(filtered_lengths, bins=min(20, len(set(filtered_lengths))), edgecolor='black', alpha=0.75)
        plt.axvline(x=8, color='red', linestyle='--', label='NIST Minimum (8 chars)')
        plt.title("Password Length Distribution (Filtered)")
        plt.xlabel("Password Length")
        plt.ylabel("Frequency (in ones)")
        plt.legend()
        plt.tight_layout()
        plt.savefig("password_length_distribution.png")
        plt.close()

        # Box plot for password lengths
        logging.info("Creating box plot for password lengths...")
        plt.boxplot(filtered_lengths, vert=False, patch_artist=True)
        plt.title("Password Length Boxplot (Filtered)")
        plt.xlabel("Password Length")
        plt.tight_layout()
        plt.savefig("password_length_boxplot.png")
        plt.close()

        outliers = [l for l in lengths if l < lower_bound or l > upper_bound]
        results_file.write(f"Number of outliers: {len(outliers)}\n")
        results_file.write(f"Example outliers: {outliers[:3]}\n")

        # Additional Data: Length vs. Frequency
        logging.info("Creating scatter plot of length vs frequency...")
        length_counts = Counter(lengths)
        lengths_unique = list(length_counts.keys())
        frequencies = list(length_counts.values())
        plt.scatter(lengths_unique, frequencies, alpha=0.6)
        plt.title("Password Length vs Frequency")
        plt.xlabel("Password Length")
        plt.ylabel("Frequency")
        plt.tight_layout()
        plt.savefig("length_vs_frequency.png")
        plt.close()

        # Predictable Passwords
        logging.info("Checking for predictable passwords...")
        predictable = check_predictable(passwords, dictionary_words)
        results_file.write(f"Predictable passwords: {len(predictable)}\n")
        results_file.write("Filtered Predictable Passwords:\n")
        for pwd in predictable[:10]:
            results_file.write(f"{pwd}\n")

        # Cracked Passwords Using Rainbow Table
        logging.info("Checking passwords against rainbow table...")
        cracked = check_rainbow_table(passwords, "rainbow")
        results_file.write(f"Cracked passwords: {len(cracked)}\n")
        results_file.write("Filtered Cracked Passwords:\n")
        for pwd, table in list(cracked.items())[:10]:
            results_file.write(f"{pwd} (cracked using {table})\n")

        # Distribution of Cracking Difficulty
        logging.info("Creating distribution graph for cracking difficulty...")
        table_counts = Counter(cracked.values())
        tables = list(table_counts.keys())
        counts = list(table_counts.values())
        plt.bar(tables, counts, color="green")
        plt.title("Distribution of Cracking Difficulty by Table")
        plt.xlabel("Rainbow Table")
        plt.ylabel("Number of Passwords Cracked")
        plt.xticks(rotation=45, ha="right")
        plt.tight_layout()
        plt.savefig("cracking_difficulty_distribution.png")
        plt.close()

        # Password Strength Evaluation
        logging.info("Evaluating password strength...")
        strength_counts = Counter(strength_check(pwd) for pwd in passwords)
        results_file.write("Password Strength Analysis:\n")
        for strength, count in strength_counts.items():
            results_file.write(f"{strength}: {count}\n")

        # Convert counts to millions for better readability
        strength_levels = list(strength_counts.keys())
        strength_values = [count / 1_000_000 for count in strength_counts.values()]  # Scale to millions

        # Plot the bar chart
        plt.bar(strength_levels, strength_values, color="blue")
        plt.title("Password Strength Breakdown")
        plt.xlabel("Strength Level")
        plt.ylabel("Frequency (in millions)")  # Correct Y-axis label
        plt.tight_layout()
        plt.savefig("password_strength_breakdown.png")
        plt.close()

if __name__ == "__main__":
    setup_logging()
    try:
        logging.info("Reading passwords from file...")
        with open("combined_output.txt", "r", encoding="utf-8") as file:
            passwords = [line.strip() for line in file.readlines() if line.strip()]
        if not passwords:
            raise ValueError("No passwords found in the file.")
    except FileNotFoundError:
        logging.error("Error: 'combined_output.txt' file not found.")
    except ValueError as ve:
        logging.error(f"Error: {ve}")
    else:
        analyze_passwords(passwords)
