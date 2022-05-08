import rsa
import pyotp
from tools import Passgen
from colorama import Fore, Back, Style


class RSA:
    def __init__(self, dir_pub, dir_priv):
        self.dir_pub = dir_pub
        self.dir_priv = dir_priv
        self.key_pub = ""
        self.key_priv = ""
        self.isLoadedBoth = False

    def create_rsa_keys(self):
        try:
            try:
                open('./keys/public.pem', 'r')
                open('./keys/private.pem', 'r')
                RSA.load_rsa_keys(self)
            except FileNotFoundError:
                print(Fore.RED + "[!} Generate RSA (1024) Keys.. " + Style.RESET_ALL)
                (self.key_pub, self.key_priv) = rsa.newkeys(1024)
                with open(f'{self.dir_pub}public.pem', 'xb') as file:
                    file.write(self.key_pub.save_pkcs1())
                with open(f'{self.dir_priv}private.pem', 'xb') as file:
                    file.write(self.key_priv.save_pkcs1())

                print(Fore.GREEN + "[+] Saved. " + Style.RESET_ALL)
        except Exception as e:
            print(Fore.RED + f"[!] Error: {e}" + Style.RESET_ALL)

    def load_rsa_keys(self):
        try:
            if self.isLoadedBoth:
                print(Fore.RED + "[!] Keys already loaded. " + Style.RESET_ALL)
            else:
                try:
                    with open(f'{self.dir_pub}public.pem', 'rb') as file:
                        self.key_pub = file.read()
                        self.key_pub = rsa.PublicKey.load_pkcs1(self.key_pub)
                        print(Fore.GREEN + "[+] Public key successfully added. " + Style.RESET_ALL)
                    with open(f'{self.dir_priv}private.pem', 'rb') as file:
                        self.key_priv = file.read()
                        self.key_priv = rsa.PrivateKey.load_pkcs1(self.key_priv)
                        print(Fore.GREEN + "[+] Private key successfully added. " + Style.RESET_ALL)
                        self.isLoadedBoth = True
                except FileNotFoundError:
                    RSA.create_rsa_keys(self)
        except Exception as e:
            print(Fore.RED + f"[!] Error: {e}" + Style.RESET_ALL)

    def crypt_text(self, string):
        try:
            if self.isLoadedBoth:
                string = string.encode('utf-8')
                print(Fore.GREEN + "[!] Successfully encrypted. " + Style.RESET_ALL)
                return rsa.encrypt(string, self.key_pub)
            else:
                print(Fore.RED + "[!] Keys aren't loaded. Please, load keys. " + Style.RESET_ALL)
        except Exception as e:
            print(Fore.RED + f"[!] Error: {e}" + Style.RESET_ALL)

    def decrypt_text(self, string):
        try:
            if self.isLoadedBoth:
                print(Fore.GREEN + "[!] Successfully decrypted. " + Style.RESET_ALL)
                return rsa.decrypt(string, self.key_priv).decode('utf-8')
            else:
                print(Fore.RED + "[!] Keys aren't loaded. Please, load keys. " + Style.RESET_ALL)
        except Exception as e:
            print(Fore.RED + f"[!] Error: {e}" + Style.RESET_ALL)

    def crypt_file(self, filename):
        try:
            if self.isLoadedBoth:
                with open(filename, 'r') as file_to_encrypt:
                    with open(f'./encrypted/{filename}.rsa1024', 'xb') as file_encrypted:
                        memo = file_to_encrypt.read().encode('utf-8')
                        encrypted = rsa.encrypt(memo, self.key_pub)
                        file_encrypted.write(encrypted)
                        print(Fore.GREEN + f"[+] Successfully encrypt {filename}" + Style.RESET_ALL)
                        file_encrypted.close()
                        file_to_encrypt.close()
            else:
                print(Fore.RED + "[!] Keys aren't loaded. Please, load keys. " + Style.RESET_ALL)
        except Exception as e:
            print(Fore.RED + f"[!] Error: {e}" + Style.RESET_ALL)

    def decrypt_file(self, filename):
        try:
            if self.isLoadedBoth:
                with open(f'./encrypted/{filename}', 'rb') as file_encrypted:
                    with open(f'./decrypted/{filename}.decrypted', 'x') as file_decrypted:
                        memo = file_encrypted.read()
                        decrypted = rsa.decrypt(memo, self.key_priv).decode('utf-8')
                        file_decrypted.write(decrypted)
                        print(Fore.GREEN + f"[+] Successfully decrypt {filename}" + Style.RESET_ALL)
                        file_decrypted.close()
                        file_encrypted.close()
            else:
                print(Fore.RED + "[!] Keys aren't loaded. Please, load keys. " + Style.RESET_ALL)
        except Exception as e:
            print(Fore.RED + f"[!] Error: {e}" + Style.RESET_ALL)


class OTP:
    def __init__(self):
        self.cryptor = RSA('./keys/', './keys/')
        try:
            try:
                open('secret', 'r')
                self.cryptor.load_rsa_keys()
                with open('secret', 'rb') as file:
                    self.otp_secret = file.read()
                self.secret = self.cryptor.decrypt_text(self.otp_secret)
                self.totp = pyotp.TOTP(self.secret)
            except FileNotFoundError:
                self.secret = pyotp.random_base32()
                self.totp = pyotp.TOTP(self.secret)
                self.cryptor.create_rsa_keys()
        except Exception as e:
            print(Fore.RED + f"[!] Error: {e}" + Style.RESET_ALL)

    def check_otp_first(self):
        try:
            pas = Passgen(8, 2)
            print(Fore.RED + "[!] Your password: " + pas.generate() + Style.RESET_ALL)
            print(Fore.RED + "[!] Please, remember it. " + Style.RESET_ALL)
            print(f'{Fore.WHITE}Secret: {Style.RESET_ALL}{Fore.RED}{self.secret}{Style.RESET_ALL}')
            while True:
                otp = str(input(Fore.RED + "[?] Let's check your Google Authentication OTP: " + Style.RESET_ALL))
                if self.totp.verify(otp):
                    print(Fore.GREEN + "[!] Code is right. " + Style.RESET_ALL)
                    with open('secret', 'wb') as file:
                        file.write(self.cryptor.crypt_text(self.secret))
                    with open('password', 'wb') as file:
                        file.write(self.cryptor.crypt_text(pas))

                    print(Fore.BLUE + "[+] Save secret.. " + Style.RESET_ALL)
                    break
        except Exception as e:
            print(Fore.RED + f"[!] Error: {e}" + Style.RESET_ALL)

    def check_otp(self):
        try:
            pas = str(input(Fore.RED + "[?] Write your password: " + Style.RESET_ALL))
            with open('password', 'rb') as file:
                pas_encrypt = file.read()
                password = str(self.cryptor.decrypt_text(pas_encrypt))
                if password == pas:
                    otp = str(input(Fore.RED + "[?] Let's check your Google Authentication OTP: " + Style.RESET_ALL))
                    if self.totp.verify(otp):
                        print(Back.GREEN + '[!] Authorizing.. ' + Style.RESET_ALL)
                        return True
                    else:
                        return False
        except Exception as e:
            print(Fore.RED + f"[!] Error: {e}" + Style.RESET_ALL)


def terminal(unlock=False):
    commands = ['help', 'encrypt_file', 'decrypt_file', 'encrypt_text', 'decrypt_text']
    _rsa = RSA('./keys/', './keys/')
    _rsa.load_rsa_keys()

    def help():
        print(commands)

    def decrypt_file(cmd):  # decrypt_file filename
        arguments = 2
        if len(cmd) != arguments:
            return Fore.RED + f"[!] Not enough arguments\n" \
                              f"Needs ({arguments})\n" \
                              f"You are given ({len(cmd)}"
        else:
            _rsa.decrypt_file(cmd[1])

    def encrypt_file(cmd):  # encrypt_file filename
        arguments = 2
        if len(cmd) != arguments:
            return Fore.RED + f"[!] Not enough arguments\n" \
                              f"Needs ({arguments})\n" \
                              f"You are given ({len(cmd)}"
        else:
            _rsa.crypt_file(cmd[1])

    def decrypt_text(cmd):  # decrypt_text text
        arguments = 2
        if len(cmd) != arguments:
            return Fore.RED + f"[!] Not enough arguments\n" \
                              f"Needs ({arguments})\n" \
                              f"You are given ({len(cmd)}"
        else:
            print(_rsa.decrypt_text(cmd[1]))

    def encrypt_text(cmd):  # encrypt_text text
        arguments = 2
        if len(cmd) != arguments:
            return Fore.RED + f"[!] Not enough arguments\n" \
                              f"Needs ({arguments})\n" \
                              f"You are given ({len(cmd)}"
        else:
            print(_rsa.crypt_text(cmd[1]))

    if unlock:
        while True:
            cmd = str(input("Write action: ")).split()  # help
            if cmd[0] == 'help':
                help()
            if cmd[0] == 'decrypt_file':
                decrypt_file(cmd)
            if cmd[0] == 'encrypt_file':
                encrypt_file(cmd)
            if cmd[0] == 'decrypt_text':
                decrypt_text(cmd)
            if cmd[0] == 'encrypt_text':
                encrypt_text(cmd)


def init():
    try:
        sec = OTP()
        try:
            open('secret', 'r')
            result = sec.check_otp()
            if result:
                terminal(unlock=True)
        except FileNotFoundError:
            sec.check_otp_first()
            init()
    except KeyboardInterrupt:
        pass


def check():
    terminal(unlock=True)


if __name__ == "__main__":
    init()
