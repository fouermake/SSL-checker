import ssl
import socket
from urllib.parse import urlparse
from datetime import datetime
import json
import os
import re

def is_valid_domain(domain):
    pattern = r'^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z]{2,})+$'
    return re.match(pattern, domain) is not None

def get_ssl_info(domain_or_ip):
    try:
        parsed_url = urlparse(domain_or_ip)
        domain = parsed_url.hostname or domain_or_ip
        port = parsed_url.port or 443

        context = ssl.create_default_context()

        with socket.create_connection((domain, port)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()

                if cert is None:
                    return {
                        'domain': domain_or_ip,
                        'type': 'Ошибка',
                        'expiry_date': 'Сертификат не найден'
                    }

                expiry_date = cert['notAfter']
                expiry_date = datetime.strptime(expiry_date, '%b %d %H:%M:%S %Y GMT').strftime('%d.%m.%Y')

                issuer = dict(x[0] for x in cert['issuer'])
                cert_name = issuer.get('commonName', 'Неизвестно')

                return {
                    'domain': domain_or_ip,
                    'type': cert_name,
                    'expiry_date': expiry_date
                }

    except ssl.SSLError as ssl_error:
        return {
            'domain': domain_or_ip,
            'type': 'Ошибка SSL',
            'expiry_date': str(ssl_error)
        }
    except Exception as e:
        return {
            'domain': domain_or_ip,
            'type': 'Ошибка',
            'expiry_date': str(e)
        }

class SSLChecker:
    def __init__(self):
        self.domains_list = []
        self.load_domains()

    def load_domains(self):
        try:
            script_dir = os.path.dirname(__file__)
            json_file_path = os.path.join(script_dir, 'domain_list.json')

            with open(json_file_path, 'r', encoding='utf-8') as config_file:
                config = json.load(config_file)
                self.domains_list = config.get('domains', [])

            print("\033[92m[INFO] Загружено доменов:", len(self.domains_list), "\033[0m")

        except FileNotFoundError:
            print("\033[93m[WARNING] Файл domain_list.json не найден.\033[0m")
        except json.JSONDecodeError:
            print("\033[91m[ERROR] Ошибка чтения JSON. Проверьте формат файла.\033[0m")

    def save_domains(self):
        domain_data = {
            "domains": self.domains_list
        }

        json_file_path = os.path.join(os.path.dirname(__file__), 'domain_list.json')

        with open(json_file_path, 'w', encoding='utf-8') as config_file:
            json.dump(domain_data, config_file, ensure_ascii=False, indent=4)

    def show_domains(self):
        if not self.domains_list:
            print("\033[93m[WARNING] Нет добавленных доменов.\033[0m")
            return
        print("\033[92mСписок добавленных доменов:\033[0m")
        for domain in self.domains_list:
            print(f" - {domain}")

    def check_ssl(self):
        if not self.domains_list:
            print("\033[93m[WARNING] Нет загруженных доменов.\033[0m")
            return
            
        for domain in self.domains_list:
            info = get_ssl_info(domain)
            print(f"\033[92mДомен:\033[0m {info['domain']}")
            print(f"\033[92mТип сертификата:\033[0m {info['type']}")
            print(f"\033[92mСрок окончания:\033[0m {info['expiry_date']}")
            print("\033[90m" + "-" * 60 + "\033[0m")

    def add_domain(self, domain):
        if not is_valid_domain(domain):
            print(f"\033[91m[ERROR] Домен '{domain}' не является допустимым.\033[0m")
            return

        if domain in self.domains_list:
            print(f"\033[93m[WARNING] Домен '{domain}' уже существует в списке.\033[0m")
            return

        self.domains_list.append(domain)
        self.save_domains()
        print(f"\033[92m[INFO] Домен '{domain}' добавлен.\033[0m")

    def remove_domain(self, domain):
        if domain in self.domains_list:
            self.domains_list.remove(domain)
            self.save_domains()
            print(f"\033[92m[INFO] Домен '{domain}' удален.\033[0m")
        else:
            print(f"\033[93m[WARNING] Этот домен '{domain}' не найден в списке.\033[0m")

def main():
    checker = SSLChecker()
    
    ssl_icon = """
\033[92m #####   #####  #           #####  #     # #######  #####  #    # ####### ######  \033[0m
\033[92m#     # #     # #          #     # #     # #       #     # #   #  #       #     # \033[0m
\033[92m#       #       #          #       #     # #       #       #  #   #       #     # \033[0m
\033[92m #####   #####  #          #       ####### #####   #       ###    #####   ######  \033[0m
\033[92m      #       # #          #       #     # #       #       #  #   #       #   #   \033[0m
\033[92m#     # #     # #          #     # #     # #       #     # #   #  #       #    #  \033[0m
\033[92m #####   #####  #######     #####  #     # #######  #####  #    # ####### #     # \033[0m
                                                                                  
Доступные команды:
\033[93m1. list \033[0m - показать список добавленных доменов.
\033[93m2. add <домен> \033[0m - добавить домен в список.
\033[93m3. remove <домен> \033[0m - удалить домен из списка.
\033[93m4. check ssl \033[0m - проверить SSL сертификаты добавленных доменов.
\033[93m5. exit \033[0m - выход из программы.
"""
    
    print(ssl_icon)
    
    while True:
        command = input("\033[92m$ \033[0m").strip().lower()

        if command == "exit":
            break
        elif command in ["list", "ls", "ll"]:
            checker.show_domains()
        elif command.startswith("add "):
            domain = command.split(" ", 1)[1]
            checker.add_domain(domain)
        elif command.startswith("remove "):
            domain = command.split(" ", 1)[1]
            checker.remove_domain(domain)
        elif command in ["check ssl", "ssl check"]:
            checker.check_ssl()
        else:
            print("\033[93m[WARNING] Неизвестная команда. Попробуйте 'list', 'add <домен>', 'remove <домен>' или 'check ssl'.\033[0m")

if __name__ == "__main__":
    main()
