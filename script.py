#!/usr/bin/python3
import sys
from tokenize import Name  # xz, copypaste
from OpenSSL import crypto  # $ pip install pyopenssl
import telebot, psycopg2
import sqlite3
import os, asyncio
import os.path
import zipfile
import shutil
import glob
import subprocess
from pathlib import Path
from datetime import datetime
import logging
from datetime import datetime
from telebot import types

bot_api = telebot.TeleBot('HIDDEN')

logging.basicConfig(filename='/opt/HIDDENbot/logs/errors_log_file.log', level=logging.ERROR)
logging.basicConfig(filename='/opt/HIDDENbot/logs/errors_log_file.log', level=logging.CRITICAL)
logging.basicConfig(filename='/opt/HIDDENbot/logs/errors_log_file.log', level=logging.WARNING)


def get_connection():
    connection = psycopg2.connect(host="127.0.0.1", user="HIDDEN", password="HIDDEN",
                                  database="HIDDEN")
    return connection


def log_cmd_users(message):
    with open("/opt/HIDDENbot/logs/errors_log_file.log", "a") as files_logs:
        files_logs.write(str(datetime.now()))
        files_logs.write(
            " Сообщение от {0} {1} (id = {2}) {3} \n".format(message.from_user.first_name, message.from_user.last_name,
                                                             str(message.from_user.id), message.document.file_name))


@bot_api.message_handler(commands=["start"])
def button(message):
    check_tg_user_database = False
    check_tg_user_test = (message.from_user.id)
    connection = get_connection()
    connection.autocommit = True
    with connection.cursor() as cursor:
        cursor.execute("""SELECT id_tguser FROM HIDDEN.consent WHERE id_tguser = %s""", [check_tg_user_test])
        aaaa = cursor.fetchone()
    if aaaa != None:
        check_tg_user_database = True
        bot_api.send_message(message.chat.id, '''any text''', parse_mode='html')
    else:
        markup = types.InlineKeyboardMarkup(row_width=1)
        item = types.InlineKeyboardButton('Согласен ✅', callback_data='answer_1')
        markup.add(item)
        text = f'''
                any text
           '''
        bot_api.send_message(message.chat.id, text, reply_markup=markup)


@bot_api.callback_query_handler(func=lambda call: True)
def callback(call):
    if call.message:
        if call.data == 'answer_1':
            check_tg_user_database = False
            check_tg_user_test = (call.from_user.id)
            connection = get_connection()
            connection.autocommit = True
            with connection.cursor() as cursor:
                cursor.execute("""SELECT id_tguser FROM HIDDEN.consent WHERE id_tguser = %s""", [check_tg_user_test])

                aaaa = cursor.fetchone()

            if aaaa != None:
                check_tg_user_database = True
                bot_api.send_message(call.message.chat.id, 'Сообщите в тех. поддержку.')

            if check_tg_user_database == False:
                time_know = str((datetime.now()))[:19]
                connection = get_connection()
                connection.autocommit = True
                with connection.cursor() as cursor:
                    cursor.execute("INSERT INTO HIDDEN.consent (id_tguser, date_consent) VALUES (%s, %s)",
                                   (str(call.from_user.id), (time_know)))
                bot_api.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.id, text='''any text ''', parse_mode="HTML")


@bot_api.message_handler(commands=["help"])
def start(m, res=False):
    text = f'''any text'''
    bot_api.send_message(m.chat.id, text, parse_mode="html")


@bot_api.message_handler(content_types=["text"])
def handle_text(message):
    bot_api.send_message(message.chat.id, 'Воспользуйтесь вспомогательной командой /help')


@bot_api.message_handler(content_types=['document'])
def handle_docs_photo(message):
    check_tg_user_database = False
    check_tg_user_test = (message.from_user.id)
    connection = get_connection()
    connection.autocommit = True
    with connection.cursor() as cursor:
        cursor.execute("""SELECT id_tguser FROM HIDDEN.consent WHERE id_tguser = (%s)""", [message.from_user.id])
        all_result = cursor.fetchone()
    if all_result != None:
        check_tg_user_database = True
    else:
        check_tg_user_database = False

    if check_tg_user_database == True:
        try:
            def validating_a_single_certificate_duplicate(src):  # Проверка сертификата на дубликат
                for i in range(0, 1):
                    check_files_errors = renamed_path_scr_errors_file(src)
                    check_codirovka = subprocess.run(["openssl", "x509", "-in", src, "-text"],
                                                     stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
                    if check_files_errors == "MII":
                        text = f"Не удалось определить кодировку сертификата {filename}."
                        bot_api.send_message(message.chat.id, text)
                        return True
                    else:
                        if check_codirovka.returncode == 0:
                            with open(src, 'rb') as der_file:  # open file cer
                                cert_Open = crypto.load_certificate(crypto.FILETYPE_PEM, der_file.read())
                        else:
                            with open(src, 'rb') as der_file:  # open file cer
                                cert_Open = crypto.load_certificate(crypto.FILETYPE_ASN1, der_file.read())
                        cert_seria_number1 = cert_Open.get_serial_number()
                        date = str(cert_Open.get_notAfter())
                        serial_number_hex = str(hex(cert_seria_number1)[2:])
                        subject = cert_Open.get_subject()
                        name_unit_test = subject.SN
                        name_unit = subject.CN
                        SN = proverka_SN(name_unit, name_unit_test)
                        snils_unit = subject.SNILS
                        if certificate_expired(date, SN, src):
                            if get_serial_number(serial_number_hex):

                                text = f"Сертификат: {serial_number_hex}, {SN} ({snils_unit}) был ранее отправлен (дубликат)."
                                bot_api.send_message(message.chat.id, text)
                                return True
                            else:
                                return False
                        else:
                            return True

            def multiple_certificate_verification_duplicate(
                    filename):  # Проверяем все сертификаты из архива на дубликат
                sum_error_certs = 0
                sum_duplicate_certs = 0
                check_file_delete = False
                for i in range(0, 1):
                    f = os.path.join(unzipdir, filename)
                    check_files_errors = renamed_path_scr_errors_file(f)
                    if check_files_errors == "MII":
                        text = f"Не удалось определить кодировку сертификата {filename}."
                        bot_api.send_message(message.chat.id, text)
                        os.replace(f, "/opt/HIDDENbot/expect/" + filename)
                        sum_error_certs = sum_error_certs + 1
                        check_file_delete = True
                        continue
                    else:
                        check_codirovka = subprocess.run(["openssl", "x509", "-in", f, "-text"],
                                                         stdout=subprocess.DEVNULL,
                                                         stderr=subprocess.STDOUT)
                        if check_codirovka.returncode == 0:
                            with open(f, 'rb') as der_file:  # open file cer
                                cert_Open = crypto.load_certificate(crypto.FILETYPE_PEM, der_file.read())
                        else:
                            with open(f, 'rb') as der_file:  # open file cer
                                cert_Open = crypto.load_certificate(crypto.FILETYPE_ASN1, der_file.read())

                    cert_seria_number1 = cert_Open.get_serial_number()
                    date = str(cert_Open.get_notAfter())
                    serial_number_hex = str(hex(cert_seria_number1)[2:])
                    subject = cert_Open.get_subject()
                    name_unit_test = subject.SN
                    name_unit = subject.CN
                    snils_unit = subject.SNILS
                    SN = proverka_SN(name_unit, name_unit_test)
                    if certificate_expired(date, SN, f):
                        if get_serial_number(serial_number_hex):
                            sum_duplicate_certs = sum_duplicate_certs + 1
                            check_file_delete = True
                            os.remove(f)
                            asyncio.run(main(serial_number_hex, SN, snils_unit))
                    else:
                        sum_error_certs += 1
                return sum_error_certs, sum_duplicate_certs, check_file_delete

            async def main(serial_number_hex, SN, snils_unit):
                await asyncio.sleep(0.11)
                text = f"Сертификат: {serial_number_hex}, {SN} ({snils_unit}) был ранее отправлен (дубликат)."
                bot_api.send_message(message.chat.id, text)

            def get_serial_number(number):
                connection = get_connection()
                connection.autocommit = True
                with connection.cursor() as cursor:
                    cursor.execute(
                        "SELECT serial_number FROM HIDDEN.certificate WHERE serial_number = %s ", (number,)
                    )
                    result = str(cursor.fetchone())
                    if result != 'None':
                        return True

            def get_snils_cert(src):  # Парсим только  один сертификат
                check_files_errors = renamed_path_scr_errors_file(src)
                check_codirovka = subprocess.run(["openssl", "x509", "-in", src, "-text"], stdout=subprocess.DEVNULL,
                                                 stderr=subprocess.STDOUT)
                if check_files_errors == "MII":
                    text = f"Не удалось определить кодировку сертификата {filename}"
                    bot_api.send_message(message.chat.id, text)
                else:
                    check_codirovka = subprocess.run(["openssl", "x509", "-in", src, "-text"],
                                                     stdout=subprocess.DEVNULL,
                                                     stderr=subprocess.STDOUT)
                    if check_codirovka.returncode == 0:
                        with open(src, 'rb') as der_file:  # open file cer
                            cert_Open = crypto.load_certificate(crypto.FILETYPE_PEM, der_file.read())
                    else:
                        with open(src, 'rb') as der_file:  # open file cer
                            cert_Open = crypto.load_certificate(crypto.FILETYPE_ASN1, der_file.read())
                serial_number = cert_Open.get_serial_number()
                serial_number_hex = str(hex(serial_number)[2:])
                subject = cert_Open.get_subject()  # https://www.pyopenssl.org/en/latest/api/crypto.html
                snils_unit = subject.SNILS  # pole snils tyanem bygagaga #OU
                OU_unit = subject.unstructuredAddress
                mail_unit = subject.emailAddress
                name_unit = subject.CN
                name_unit_test = subject.SN
                ogrn_unit = subject.OGRN
                inn_unit = subject.INN
                issuer = cert_Open.get_issuer()
                name_unit_issuer = issuer.CN

                return [snils_unit, OU_unit, mail_unit, name_unit, name_unit_test, serial_number_hex,inn_unit,ogrn_unit,name_unit_issuer]

            def renamed_path_scr_errors_file(
                    scr):  # проверяем первые три символа сертификата для отлова баги с кодировкой (----begin----- -----end-----)
                file_test = open(scr, "r", errors='ignore').read(3)
                return file_test

            def inside_zip(src):  # src - путь до архива.Смотрим что лежит в архиве
                correct_extension = False
                with zipfile.ZipFile(src) as archive:
                    for zip_info in archive.infolist():
                        if zip_info.filename[-1] == '/':  # Скипаем папки
                            continue
                        if (Path(str(zip_info)).suffix[:4]) != ".cer":
                            correct_extension = True
                            break
                    return correct_extension

            def filename_check_serial_number(filename):  # для записи в бд серийника
                check_codirovka = subprocess.run(["openssl", "x509", "-in", filename, "-text"],
                                                 stdout=subprocess.DEVNULL,
                                                 stderr=subprocess.STDOUT)
                if check_codirovka.returncode == 0:
                    with open(filename, 'rb') as der_file:  # open file cer
                        cert_Open = crypto.load_certificate(crypto.FILETYPE_PEM, der_file.read())
                else:
                    with open(filename, 'rb') as der_file:  # open file cer
                        cert_Open = crypto.load_certificate(crypto.FILETYPE_ASN1, der_file.read())
                cert_seria_number1 = cert_Open.get_serial_number()
                serial_number_hex = str(hex(cert_seria_number1)[2:])
                return serial_number_hex

            def extract_dir(src):  # выгрузка всех сертификатов в папку unzipdir
                with zipfile.ZipFile(src) as archive:
                    i = 0
                    for zip_info in archive.infolist():
                        if zip_info.filename[-1] == '/':
                            continue
                        zip_info.filename = os.path.basename(zip_info.filename)
                        archive.extract(zip_info, unzipdir)
                        s = str(zip_info)
                        s = s[s.find("'")+1:]
                        s= s[:s.find("'")]
                        os.rename(unzip_dir + f"/{s}", unzip_dir + f"/{i}.cer" )
                        i += 1

            def renamed(dirpath, names, encoding="cp866"):  # переименование серт-ов
                new_names = [old.encode('cp437').decode(encoding) for old in names]
                for old, new in zip(names, new_names):
                    os.rename(os.path.join(dirpath, old), os.path.join(dirpath, new))
                return new_names

            def get_snils(filename):  # Получаем из сертификата опред-ые поля
                f = os.path.join(unzipdir, filename)
                check_codirovka = subprocess.run(["openssl", "x509", "-in", f, "-text"], stdout=subprocess.DEVNULL,
                                                 stderr=subprocess.STDOUT)
                if check_codirovka.returncode == 0:
                    with open(f, 'rb') as der_file:  # open file cer
                        cert_Open = crypto.load_certificate(crypto.FILETYPE_PEM, der_file.read())
                else:
                    with open(f, 'rb') as der_file:  # open file cer
                        cert_Open = crypto.load_certificate(crypto.FILETYPE_ASN1, der_file.read())
                serial_number = cert_Open.get_serial_number()
                serial_number_hex = str(hex(serial_number)[2:])
                subject = cert_Open.get_subject()  # https://www.pyopenssl.org/en/latest/api/crypto.html
                snils_unit = subject.SNILS  # pole snils tyanem bygagaga #OU
                OU_unit = subject.unstructuredAddress
                mail_unit = subject.emailAddress
                name_unit = subject.CN
                name_unit_test = subject.SN
                ogrn_unit = subject.OGRN
                inn_unit = subject.INN
                issuer = cert_Open.get_issuer()
                name_unit_issuer = issuer.CN
                
                return [snils_unit, OU_unit, mail_unit, name_unit, name_unit_test, serial_number_hex,inn_unit,ogrn_unit,name_unit_issuer]

            def proverka_SN(CN, SN):  # Проверка поля SN
                if SN != None:
                    CN = SN
                return CN

            def get_database_snils(snils,ogrn,CN):  # выгрузка с бд retest
                status_certs = False
                connection = get_connection()
                connection.autocommit = True
            
                with connection.cursor() as cursor:
                    if (ogrn == None) and (CN == "HIDDEN" or CN == "HIDDEN"):
                        cursor.execute("SELECT snils FROM HIDDEN.users WHERE snils = %s",(snils,))
                    else:
                        cursor.execute("""SELECT snils From HIDDEN.users INNER JOIN HIDDEN.organization ON users.snils = %s and organization.ogrn = %s""",(snils, ogrn))
                    all_result = str(cursor.fetchone())  # перекидываем все значения из столбца СНИЛС
                    if all_result != 'None':
                        status_certs = True
                return status_certs

            def sum_of_certificate():  # Считаем изначальное количество сертификатов которые есть в архиве
                cert_count = 0
                for file in os.listdir(unzipdir):
                    cert_count += 1
                return cert_count

            def delete_dir(dir1, dir2):  # удаляем папочки присланные
                shutil.rmtree(dir1)
                shutil.rmtree(dir2)

            def certificate_expired(date, SN, f):
                hour_change = str(int(date[10:12]) + 3)
                sert_after = str((date[2:6] + '-' + date[6:8] + "-" + date[8:10] + " " + hour_change + ":" + date[
                                                                                                             12:14] + ":" + date[
                                                                                                                            14:16]))
                time_know = str((datetime.now()))[:19]
                if sert_after < time_know:
                    text = f"Сертификат {SN} просрочен."
                    bot_api.send_message(message.chat.id, text)
                    os.remove(f)
                    return False
                else:
                    return True

            def get_user_id(number):
                connection = get_connection()
                connection.autocommit = True
                with connection.cursor() as cursor:
                    cursor.execute(
                        "SELECT user_id FROM HIDDEN.users WHERE snils = %s;", (number,)
                    )
                    result = str(cursor.fetchall()).partition(",")[0][2:]
                    return result

            def get_cert_after(filename):  # Сколько  сейчас время и то какого числа робит серт

                f = os.path.join(unzipdir, filename)
                check_codirovka = subprocess.run(["openssl", "x509", "-in", f, "-text"], stdout=subprocess.DEVNULL,
                                                 stderr=subprocess.STDOUT)
                if check_codirovka.returncode == 0:
                    with open(f, 'rb') as der_file:  # open file cer
                        cert_Open = crypto.load_certificate(crypto.FILETYPE_PEM, der_file.read())
                else:
                    with open(f, 'rb') as der_file:  # open file cer
                        cert_Open = crypto.load_certificate(crypto.FILETYPE_ASN1, der_file.read())
                date = str(cert_Open.get_notAfter())
                hour_change = str(int(date[10:12]) + 3)
                sert_after = str((date[2:6] + '-' + date[6:8] + "-" + date[8:10] + " " + hour_change + ":" + date[
                                                                                                             12:14] + ":" + date[
                                                                                                                            14:16]))
                return sert_after

            chat_id = message.chat.id
            file_info = bot_api.get_file(message.document.file_id)
            downloaded_file = bot_api.download_file(file_info.file_path)
            cert_dir = "/opt/HIDDEN/cert_" + str(datetime.now())
            os.mkdir(cert_dir)
            unzip_dir = "/opt/HIDDEN/unzip_" + str(datetime.now())
            os.mkdir(unzip_dir)
            src = str(cert_dir) + "/" + message.document.file_name
            with open(src, 'wb') as new_file:
                new_file.write(downloaded_file)
            log_cmd_users(message)
            good_certs = '/opt/HIDDEN/good_certs/'
            new_certs = '/opt/HIDDEN/new_certs/'
            bad_certs = '/opt/HIDDEN/bad_certs/'
            unzipdir = unzip_dir + "/"
            if (Path(str(src)).suffix[:4]) == ".cer":
                for i in range(0, 1):
                    if validating_a_single_certificate_duplicate(src):
                        delete_dir(cert_dir, unzip_dir)
                        break
                    else:
                        cert = get_snils_cert(src)
                        cert[4] = proverka_SN(cert[3], cert[4])
                        status_certs = get_database_snils(cert[0],cert[7],cert[8])
                        if status_certs:
                            id_user = get_user_id(cert[0])
                            serial_number_for_database = filename_check_serial_number(src)
                            valid_until = get_cert_after(src)
                            rename = shutil.move(src, os.path.join(src[:src.rfind("/")], f"{cert[5]}.cer"))
                            shutil.copy(rename, good_certs)
                            shutil.copy(os.path.join(good_certs, f"{cert[5]}.cer"), new_certs)
                            time_know = str((datetime.now()))[:19]
                            tguser_id = str(message.from_user.id)
                            connection = get_connection()
                            connection.autocommit = True
                            with connection.cursor() as cursor:
                                cursor.execute(
                                    "INSERT INTO HIDDEN.certificate (user_id, serial_number,id_tguser,valid_until,date_download) VALUES (%s, %s,%s,%s,%s)",
                                    (id_user, serial_number_for_database, tguser_id, valid_until, time_know))
                            text = f'anytext ({serial_number_for_database}) any tet'
                            bot_api.send_message(message.chat.id, text)
                        else:
                            os.rename(src, bad_certs + f"{cert[5]}.cer")
                            text = f'{cert[4]}({cert[0]}) any text'
                            bot_api.send_message(message.chat.id, text)
                        delete_dir(cert_dir, unzip_dir)
            else:
                for i in range(0, 1):
                    inside_zip = inside_zip(src)
                    if inside_zip:
                        text = f"В архиве должны находится только файлы с расширением .cer"
                        bot_api.send_message(message.chat.id, text)
                        delete_dir(cert_dir, unzip_dir)
                        break
                    else:
                        extract_dir(src)
                        os.chdir(unzipdir)  # cd to avoid reencoding the parent dirname
                        for dirpath, dirs, files in os.walk(os.curdir, topdown=True):
                            renamed(dirpath, files)
                            dirs[:] = renamed(dirpath, dirs)
                        good_users = 0
                        bad_users = 0
                        cert_count = int(sum_of_certificate())
                        text = f"Количество сертификатов принятых в обработку: {cert_count}."
                        bot_api.send_message(message.chat.id, text)
                        all_errors_dubl_erros = 0
                        for filename in os.listdir(unzipdir):
                            sum_error_certs, sum_duplicate_certs, check_file_delete = multiple_certificate_verification_duplicate(
                                filename)
                            all_errors_dubl_erros = all_errors_dubl_erros + sum_error_certs + sum_duplicate_certs
                            if check_file_delete:
                                continue
                            cert = get_snils(filename)
                            cert[4] = proverka_SN(cert[3], cert[4])
                            status_certs = get_database_snils(str(cert[0]),cert[7],cert[8])
                            if status_certs:
                                good_users += 1
                                serial_number_for_database = filename_check_serial_number(filename)
                                valid_until = get_cert_after(filename)
                                rename = shutil.move((os.path.join(unzipdir, filename)),
                                                     os.path.join(unzip_dir, f"{cert[5]}.cer"))
                                shutil.copy(os.path.join(unzipdir, rename), good_certs)
                                shutil.copy(os.path.join(unzipdir, rename), new_certs)
                                id_user = get_user_id(cert[0])
                                tguser_id = str(message.from_user.id)
                                time_know = str((datetime.now()))[:19]
                                connection = get_connection()
                                connection.autocommit = True
                                with connection.cursor() as cursor:
                                    cursor.execute(
                                        "INSERT INTO HIDDEN.certificate (user_id, serial_number,id_tguser,valid_until,date_download) VALUES (%s, %s,%s,%s,%s)",
                                        (id_user, serial_number_for_database, tguser_id, valid_until, time_know))
                            else:
                                bad_users += 1
                                os.rename(os.path.join(unzipdir, filename), bad_certs + f"{cert[5]}.cer")
                                text = f'any text {cert[4]}({cert[0]}) any text'
                                bot_api.send_message(message.chat.id, text)
                    if good_users == cert_count:
                        text = f"any text {cert_count} из {cert_count} any text"
                        bot_api.send_message(message.chat.id, text)
                        delete_dir(cert_dir, unzip_dir)
                    else:
                        end_user = cert_count - bad_users - all_errors_dubl_erros
                        text = f"any text {end_user} из {cert_count} any text"
                        bot_api.send_message(message.chat.id, text)
                        delete_dir(cert_dir, unzip_dir)
        except Exception as e:
            bot_api.reply_to(message, e)
            logging.exception("message")
            shutil.rmtree(cert_dir)
            shutil.rmtree(unzip_dir)
    else:
        text = f'Для взаимодействия с ботом необходимо принять согласие на обработку персональных данных, нажав кнопку Согласен ✅.'
        bot_api.send_message(message.chat.id, text, parse_mode="html")


bot_api.polling(none_stop=True, interval=0, timeout=120)
