import itertools
import argparse
import string
import boto3
from datetime import datetime, timezone, timedelta

def gprint_password_policy(profile_name=None):
    session = boto3.Session(profile_name=profile_name)
    iam_client = session.client("iam")
    try:
        policy_keys = ["AllowUsersToChangePassword", "ExpirePasswords", "HardExpiry",
                       "MaxPasswordAge", "MinimumPasswordLength", "PasswordReusePrevention",
                       "RequireLowercaseCharacters", "RequireNumbers", "RequireSymbols", "RequireUppercaseCharacters"]
        response = iam_client.get_account_password_policy()
        pass_pol = response["PasswordPolicy"]

        response = iam_client.get_account_password_policy()
        pass_pol = response["PasswordPolicy"]
        for key in policy_keys:
            if key not in pass_pol.keys():
                pass_pol[key] = "Not Set"
        table_data = [["".join([" " + char if i > 0 and char.isupper() else char for i, char in enumerate(key)]),
                       str(value)] for key, value in pass_pol.items()]
        col_widths = [max(len(row[0]) for row in table_data),
                      max(len(str(row[1])) for row in table_data)]
        separator = f"+{'-' * (col_widths[0] + 2)}+{'-' * (col_widths[1] + 2)}+"
        header = f"| {'Policy Setting'.ljust(col_widths[0])} | {'Value'.ljust(col_widths[1])} |"
        output = [separator, header, separator]
        for row in table_data:
            output.append(f"| {row[0].ljust(col_widths[0])} | {row[1].ljust(col_widths[1])} |")
        output.append(separator)
        print("\n".join(output))
    except iam_client.exceptions.NoSuchEntityException:
        return "No password policy is set for this account."
    except Exception as e:
        return f"Error retrieving password policy: {str(e)}"

def use_account_pass_pol(profile, args):
    session = boto3.Session(profile_name=profile)
    iam_client = session.client("iam")
    try:
        response = iam_client.get_account_password_policy()
        pass_pol = response["PasswordPolicy"]
        args.require_length = pass_pol.get('MinimumPasswordLength', args.require_length)
        args.require_upper = pass_pol.get('RequireUpperCaseCharacters', args.require_upper)
        args.require_lower = pass_pol.get('RequireLowerCaseCharacters', args.require_lower)
        args.require_digit = pass_pol.get('RequreNumbers', args.require_digit)
        args.require_special = pass_pol.get('RequireSymbols', args.require_special)
        return args
    except iam_client.exceptions.NoSuchEntityException:
        print(f"No password policy found with AWS profile: {profile}")
        return args
    except Exception as error:
        print(f"Failed to pull AWS password policy from profile {profile}")
        print(f"Error: {error}")
        return args

def get_user_password_last_set(profile_name, user_name):
    session = boto3.Session(profile_name=profile_name)
    iam_client = session.client("iam")
    response = iam_client.get_login_profile(UserName=user_name)
    last_set = response['LoginProfile']["CreateDate"].replace(tzinfo=timezone.utc)
    now = datetime.now(timezone.utc)
    age_days = (now - last_set).days
    return age_days

def create_year_seasons_words(last_set_days):
    target_date = datetime.now() - timedelta(days=last_set_days)
    year = target_date.year
    previous_year = year - 1

    seasons = {"Winter": (datetime(previous_year, 12, 21), datetime(year, 3, 19)), 
               "Spring": (datetime(year, 3, 20), datetime(year, 6, 20)),
               "Summer": (datetime(year, 6, 21), datetime(year, 9, 22)),
               "Fall": (datetime(year, 9, 23), datetime(year, 12, 20))}
    current_season = None
    previous_season = None
    season_names = list(seasons.keys())

    for i, (season, (start, end)) in enumerate(seasons.items()):
        if start <= target_date < end:
            current_season = season
            previous_season = season_names[i - 1] if i > 0 else "Winter"

    wordlist = [str(year), 
                target_date.strftime("%B"),
                # target_date.strftime("%b"),
                current_season, 
                previous_season]
    if current_season == "Winter" and target_date.month < 3:
        wordlist.append(str(previous_year))
    if previous_season == "Winter":
        wordlist.append(str(previous_year))

    return list(set(wordlist))

def simple_mutate_words(words):
    mutated_list = []
    for word in words:
        mutated_list.append(word)
        if word[0].isalpha():
            mutated_list.append((word[:1].lower() if word[0].isupper() else word[:1].upper()) + word[1:])
    return mutated_list

def alpha_mutate_words(words):
    expanded_words = set()
    for word in words:
        expanded_words.update([''.join(p) for p in itertools.product(*[(c.lower(), c.upper()) for c in word])])
    return list(expanded_words)

def generate_passwords(words, max_words, max_length, max_duplicates, loosey_dedup, require_length, require_upper, require_lower, require_digit, require_special):
    valid_passwords = []
    for num_words in range(1, max_words + 1):
        for combination in itertools.permutations(words, r=num_words):
            password = "".join(combination)
            if len(password) > max_length:
                continue
            if not duplicates_check(password, words, max_duplicates, loosey_dedup):
                continue
            if meets_password_policy(password, require_length, require_upper, require_lower, require_digit, require_special):
                valid_passwords.append(password)
    return valid_passwords

def duplicates_check(password, words, max_duplicates, loosey_dedup):
    for word in words:
        if loosey_dedup:
            if password.lower().count(word.lower()) > max_duplicates:
                return False
        if password.count(word) > max_duplicates:
            return False
    return True

def meets_password_policy(password, min_length, require_upper, require_lower, require_digit, require_special):
    if len(password) < min_length:
        return False
    has_upper = any(c.isupper() for c in password) if require_upper else True
    has_lower = any(c.islower() for c in password) if require_lower else True
    has_digit = any(c.isdigit() for c in password) if require_digit else True
    has_special = any(c in string.punctuation for c in password) if require_special else True
    return all([has_upper, has_lower, has_digit, has_special])

# Main function
def main():
    parser = argparse.ArgumentParser(description="Generate AWS-compliant passwords from wordlist.")
    parser.add_argument("-file", help="file containing key-words with one per line")
    parser.add_argument("-key-words", nargs="+", help="Specify key words directly")    
    parser.add_argument("-max-words", type=int, default=4, help="Maximum words to combine")
    parser.add_argument("-max-length", type=int, default=20, help="Maximum password length")
    parser.add_argument("-max-duplicates", type=int, default=2, help="Maximum duplicate words in a password")
    parser.add_argument("-loosey-dedup", default=False, action="store_true", help="Remove duplicates that appear in a password regardless of case.")
    parser.add_argument("-simple-mutate", default=False, action="store_true", help="Add upper/lower capitalization of first character for each alpha.")
    parser.add_argument("-alpha-mutate", default=False, action="store_true", help="Mutate all characters in each word for all lower/upper combinations.")
    parser.add_argument("-require-length", type=int, default=8, help="Minimum password count")
    parser.add_argument("-require-upper", type=int, default=1, help="Minimum upper-case count")
    parser.add_argument("-require-lower", type=int, default=1, help="Minimum lower-case count")
    parser.add_argument("-require-digit", type=int, default=1, help="Minimum digit count")
    parser.add_argument("-require-special", type=int, default=1, help="Minimum special character count")
    parser.add_argument("-use-account-pass-pol", type=str, default="", help="Pull password policy from AWS profile (will override other 'require' arguments.)")
    parser.add_argument("-get-pass-pol", type=str, default="", help="Just reports the password policy for the provided account")
    parser.add_argument("-target-user", type=str, default="", help="Create password combos using provided words and replacing year and season relevant to when they last changed their password (requires -use-account-pass-pol as well and will remove other years/seasons from key-words list)")
    parser.add_argument("-target-days", type=int, default=0, help="Same as -target-user, but you specify the number of days. (Will remove other years/seasons from key-words list)")

    args = parser.parse_args()

    if args.get_pass_pol:
        gprint_password_policy(args.get_pass_pol)
        print()
        exit

    if args.use_account_pass_pol:
        args = use_account_pass_pol(args.use_account_pass_pol, args)

    words = []
    if args.key_words:
        words.extend(args.key_words)
    if args.file:
        with open(args.file, "r", encoding="utf-8") as f:
            words.extend(line.strip() for line in f if line.strip())

    if not words:
        print("Error: No words provided. Use -word or -file.")
        return

    if args.use_account_pass_pol and args.target_user:
        words = [w for w in words if not (w.isdigit() and 1900 <= int(w) <= 2099)]
        seasons = ["Winter", "Spring", "Summer", "Fall"]
        words = [w for w in words if isinstance(w, str) and w not in seasons and w not in (s.lower() for s in seasons)]
        last_set_days = get_user_password_last_set(args.use_account_pass_pol, args.target_user)
        words.extend(create_year_seasons_words(last_set_days))
        words = list(set(words))

    if args.target_user and args.target_days:
        print("Slow your roll. I can't do both look aws user days and specifying specific days.")
    elif args.target_days:
        words = [w for w in words if not (w.isdigit() and 1900 <= int(w) <= 2099)]
        seasons = ["Winter", "Spring", "Summer", "Fall"]
        words = [w for w in words if isinstance(w, str) and w not in seasons and w not in (s.lower() for s in seasons)]
        words.extend(create_year_seasons_words(args.target_days))

    if args.simple_mutate and args.alpha_mutate:
        print("Slow your roll. I can't do both simple and alpha mutate.")
        exit
    elif args.simple_mutate:
        words = simple_mutate_words(words)
    elif args.alpha_mutate:
        words = alpha_mutate_words(words)

    passwords = generate_passwords(words, 
                                   args.max_words, args.max_length, args.max_duplicates, args.loosey_dedup,
                                   args.require_length, args.require_upper, args.require_lower, 
                                   args.require_digit, args.require_special)

    for password in passwords:
        print(password)

if __name__ == "__main__":
    main()
