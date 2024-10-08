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

        expiry_date_str = 'Неизвестно'

        try:
            sock = await loop.run_in_executor(None, socket.create_connection, (domain, port))
        except (socket.gaierror, socket.error):
            return {'domain': domain_or_ip, 'type': 'Ошибка соединения', 'expiry_date': 'Не удалось установить подключение'}

        try:
            ssock = context.wrap_socket(sock, server_hostname=domain)
            cert = ssock.getpeercert()

            if cert is None:
                return {'domain': domain_or_ip, 'type': 'Ошибка', 'expiry_date': 'Сертификат не найден'}

            expiry_date = cert['notAfter']
            expiry_date_dt = datetime.strptime(expiry_date, '%b %d %H:%M:%S %Y GMT')
            expiry_date_str = expiry_date_dt.strftime('%d.%m.%Y')

            issuer = dict(x[0] for x in cert['issuer'])
            cert_name = issuer.get('commonName', 'Неизвестно')

            if expiry_date_dt < datetime.now():
                return {'domain': domain_or_ip, 'type': 'Сертификат истёк', 'expiry_date': expiry_date_str}

            return {'domain': domain_or_ip, 'type': cert_name, 'expiry_date': expiry_date_str}

        except ssl.SSLError as ssl_error:
            error_message = str(ssl_error)
            if "certificate has expired" in error_message:
                return {'domain': domain_or_ip, 'type': 'Сертификат истёк', 'expiry_date': expiry_date_str}
            elif "self-signed certificate" in error_message:
                return {'domain': domain_or_ip, 'type': 'Самоподписанный сертификат', 'expiry_date': expiry_date_str}
            else:
                return {'domain': domain_or_ip, 'type': 'Ошибка SSL', 'expiry_date': str(ssl_error)}

    except Exception as e:
        return {'domain': domain_or_ip, 'type': 'Ошибка', 'expiry_date': str(e)}

class SSLChecker:
    def __init__(self):
        self.domains_list = []
        self.load_domains()

    def load_domains(self):
        script_dir = os.path.dirname(__file__)
        json_file_path = os.path.join(script_dir, 'domain_list.json')

        if os.path.exists(json_file_path):
            try:
                with open(json_file_path, 'r', encoding='utf-8') as config_file:
                    config = json.load(config_file)
                    self.domains_list = config.get('domains', [])
                print(f"\033[92m[INFO] Загружено доменов: {len(self.domains_list)}\033[0m")
            except json.JSONDecodeError:
                print("\033[91m[ERROR] Ошибка чтения JSON. Проверьте формат файла.\033[0m")
        else:
            print("\033[93m[WARNING] Файл domain_list.json не найден. Начните с добавления доменов.\033[0m")

    async def save_domains(self):
        domain_data = {"domains": self.domains_list}
        json_file_path = os.path.join(os.path.dirname(__file__), 'domain_list.json')

        async with aiofiles.open(json_file_path, 'w', encoding='utf-8') as config_file:
            await config_file.write(json.dumps(domain_data, ensure_ascii=False, indent=4))

    async def show_domains(self):
        if not self.domains_list:
            print("\033[93m[WARNING] Нет добавленных доменов.\033[0m")
            return
        print("\033[92mСписок добавленных доменов:\033[0m")
        for domain in self.domains_list:
            print(f" - {domain.replace('http://', '').replace('https://', '')}")

    async def check_ssl(self):
        if not self.domains_list:
            print("\033[93m[WARNING] Нет загруженных доменов.\033[0m")
            return
            
        print("\033[93m[INFO] Начинается проверка SSL сертификатов. Пожалуйста, подождите...\033[0m")
        
        results = await asyncio.gather(*(get_ssl_info(domain) for domain in self.domains_list))

        print("\n\033[92m{: <30} {: <50} {: <10}\033[0m".format("Домен", "Тип сертификата", "Дата окончания"))
        print("-" * 100)
        for info in results:
            print("{: <30} {: <50} {: <10}".format(info['domain'], info['type'], info['expiry_date']))

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
            domain = domain.replace('http://', '').replace('https://', '').strip()
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
        stripped_domain = domain.replace('http://', '').replace('https://', '').strip()
        if stripped_domain in self.domains_list:
            self.domains_list.remove(stripped_domain)
            await self.save_domains()
            print(f"\033[92m[INFO] Домен '{stripped_domain}' удален.\033[0m")
        else:
            print(f"\033[93m[WARNING] Домен '{stripped_domain}' не найден в списке.\033[0m")

    async def remove_domains(self, domains):
        removed_domains = []
        for domain in domains:
            stripped_domain = domain.replace('http://', '').replace('https://', '').strip()
            if stripped_domain in self.domains_list:
                self.domains_list.remove(stripped_domain)
                removed_domains.append(stripped_domain)
            else:
                print(f"\033[93m[WARNING] Домен '{stripped_domain}' не найден в списке.\033[0m")

        await self.save_domains()

        if removed_domains:
            print(f"\033[92m[INFO] Удалены домены: {', '.join(removed_domains)}.\033[0m")

    async def show_github_info(self):
        github_info = {
            "domain": "https://github.com/fouermake",
            "author": "fouermake",
            "creation_date": "09.03.2024"
        }

        print("\n\033[92m{: <50} {: <20} {: <25}\033[0m".format("Домен", "Автор", "Дата создания программы"))
        print("-" * 100)
        print("{: <50} {: <20} {: <25}".format(github_info['domain'], github_info['author'], github_info['creation_date']))

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
\033[93m1. list (ll, ls)\033[0m - показать список добавленных доменов.
\033[93m2. add <домен1, домен2, ...>\033[0m - добавить домены в список (через запятую).
\033[93m3. remove (rm) <домен1, домен2, ...>\033[0m - удалить домены из списка (через запятую).
\033[93m4. check ssl\033[0m - проверить SSL сертификаты добавленных доменов.
\033[93m6. exit\033[0m - выход из программы.
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
            domains = command.split(" ", 1)[1].split(",") 
            domains = [domain.strip() for domain in domains]  
            await checker.remove_domains(domains)
        elif command in ["check ssl", "ssl check"]:
            await checker.check_ssl()
        elif command == "git":
            await checker.show_github_info()
        else:
            print("\033[93m[WARNING] Неизвестная команда. Попробуйте 'list', 'add <домен...>', 'remove <домен>' или 'check ssl'.\033[0m")

if __name__ == "__main__":
    asyncio.run(main())
