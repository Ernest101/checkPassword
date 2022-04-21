"""
App checks if your password contains at least:
    1. 8 chars lenght
    2. One upper letter
    3. One lower letter
    4. One digit
    5. One special character
and finally if the password has been pwned

App reads file 'passwords.txt'. The file has to contain one password each line.
In case of password not pass some test it raises ValidationError ang log it to infos.log file.
Password that passed all tests is written to file 'checked.txt' (one password each line).
"""

import logging
from validators import (PasswordValidator,
                        LengthValidator,
                        DigitValidator,
                        SpecialCharValidator,
                        UpperValidator,
                        LowerValidator,
                        PwnedValidator,
                        ValidationError)
logging.basicConfig(filename='infos.log', level=logging.INFO)


class Main:
    """ Call it to run program """

    @staticmethod
    def check_pass() -> None:
        """ Function opens file 'passwords.txt', read it line by line, checks validators,
            password tested positive are written to 'checked.txt'. Validation results are logged """
        try:
            with open('passwords.txt', 'r', encoding='utf8') as f_read, \
                    open('checked.txt', 'w', encoding='utf8') as f_write:
                for num, line in enumerate(f_read, start=1):
                    try:
                        password = PasswordValidator(line.strip())
                        password.is_valid()
                        f_write.write(f'{password.get_password()}\r')
                        logging.info(f'Password no. {num} is safe')
                    except ValidationError as error2:
                        print(error2)
                        logging.info(f'Password no. {num} is not safe. {error2}')
        except FileNotFoundError as error1:
            print(f'No such file: {error1.filename}')


if __name__ == '__main__':
    main = Main()
    main.check_pass()
