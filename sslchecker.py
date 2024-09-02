import ssl
import socket
import asyncio
from urllib.parse import urlparse
from datetime import datetime
import json
import os
import re
import pandas as pd
import aiofiles

def is_valid_domain(domain):
    pattern = r'^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z]{2,})+$'
    return re.match(pattern, domain) is not None

async def get_ssl_info(domain_or_ip):
    try:
        parsed_url = urlparse(domain_or_ip)
        domain = parsed_url.hostname or domain_or_ip
        port = parsed_url.port or 443

        context = ssl.create_default_context()

        loop = asyncio.get_event_loop()
        sock = await loop.run_in_executor(None, socket.create_connection, (domain, port))
        ssock = context.wrap_socket(sock, server_hostname=domain)

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

    async def save_domains(self):
        domain_data = {
            "domains": self.domains_list
        }

        json_file_path = os.path.join(os.path.dirname(__file__), 'domain_list.json')

        async with aiofiles.open(json_file_path, 'w', encoding='utf-8') as config_file:
            await config_file.write(json.dumps(domain_data, ensure_ascii=False, indent=4))

    async def show_domains(self):
        if not self.domains_list:
            print("\033[93m[WARNING] Нет добавленных доменов.\033[0m")
            return
        print("\033[92mСписок добавленных доменов:\033[0m")
        for domain in self.domains_list:
            print(f" - {domain}")

    async def check_ssl(self):
        if not self.domains_list:
            print("\033[93m[WARNING] Нет загруженных доменов.\033[0m")
            return
            
        print("\033[93m[INFO] Начинается проверка SSL сертификатов. Пожалуйста, подождите...\033[0m")

        results = await asyncio.gather(
            *(get_ssl_info(domain) for domain in self.domains_list)
        )

        for info in results:
            print(f"\033[92mДомен:\033[0m {info['domain']}")
            print(f"\033[92mТип сертификата:\033[0m {info['type']}")
            print(f"\033[92mСрок окончания:\033[0m {info['expiry_date']}\n")
            print("\033[90m" + "-" * 60 + "\033[0m")

        save_choice = input("\033[93mХотите сохранить результаты? (y/n): \033[0m").strip().lower()
        if save_choice == 'y':
            await self.save_results(results)
        else:
            print("\033[92m[INFO] Результаты не сохранены.\033[0m")

    async def save_results(self, results):
        format_choice = input("\033[93mВыберите формат для сохранения результатов (1 - текстовый файл, 2 - Excel): \033[0m").strip()

        if format_choice == '1':
            file_path = os.path.join(os.path.dirname(__file__), 'ssl_results.txt')
            async with aiofiles.open(file_path, 'w', encoding='utf-8') as f:
                for result in results:
                    await f.write(f"Домен: {result['domain']}, Тип: {result['type']}, Срок окончания: {result['expiry_date']}\n")
            print(f"\033[92m[INFO] Результаты сохранены в '{file_path}'.\033[0m")

        elif format_choice == '2':
            df = pd.DataFrame(results)
            file_path = os.path.join(os.path.dirname(__file__), 'ssl_results.xlsx')
            df.to_excel(file_path, index=False)
            print(f"\033[92m[INFO] Результаты сохранены в '{file_path}'.\033[0m")
        else:
            print("\033[91m[ERROR] Неверный выбор формата.\033[0m")

    async def add_domains(self, domains):
        added_domains = []
        for domain in domains:
            if not is_valid_domain(domain):
                print(f"\033[91m[ERROR] Домен '{domain}' не является допустимым.\033[0m")
                continue

            if domain in self.domains_list:
                print(f"\033[93m[WARNING] Домен '{domain}' уже существует в списке.\033[0m")
                continue

            self.domains_list.append(domain)
            added_domains.append(domain)
        
        await self.save_domains()
        
        if added_domains:
            print(f"\033[92m[INFO] Добавлены домены: {', '.join(added_domains)}.\033[0m")

    async def remove_domain(self, domain):
        if domain in self.domains_list:
            self.domains_list.remove(domain)
            await self.save_domains()
            print(f"\033[92m[INFO] Домен '{domain}' удален.\033[0m")
        else:
            print(f"\033[93m[WARNING] Этот домен '{domain}' не найден в списке.\033[0m")

async def main():
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
\033[93m2. add <домен1, домен2, ...> \033[0m - добавить домены в список (через запятую).
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
            await checker.show_domains()
        elif command.startswith("add "):
            domains = command.split(" ", 1)[1].split(",")
            domains = [domain.strip() for domain in domains]
            await checker.add_domains(domains)
        elif command.startswith("remove ") or command.startswith("rm "):
            domain = command.split(" ", 1)[1]
            await checker.remove_domain(domain)
        elif command in ["check ssl", "ssl check"]:
            await checker.check_ssl()
        else:
            print("\033[93m[WARNING] Неизвестная команда. Попробуйте 'list', 'add <домен...>', 'remove <домен>' или 'check ssl'.\033[0m")

if __name__ == "__main__":
    asyncio.run(main())
