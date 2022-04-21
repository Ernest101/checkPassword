from abc import ABC, abstractmethod
from hashlib import sha1
from requests import get


class ValidationError(Exception):
    """ Exception for validation error """


class Validator(ABC):
    """ Interface for validators """
    @abstractmethod
    def __init__(self, password):
        """ Force to implement __init__ method """

    @abstractmethod
    def is_valid(self):
        """ Force to implement is_valid method """


class PasswordValidator(Validator):
    """ Contain ref to all validators"""

    def __init__(self, password):
        self._password = password
        self.validators = [
            LengthValidator,
            DigitValidator,
            SpecialCharValidator,
            UpperValidator,
            LowerValidator,
            PwnedValidator
        ]

    def is_valid(self):
        """ calls all validators one by one till ValidationError is raised, or all validation are passed
        :raise ValidationError
           password length < 8 chars
        :returns Bool
           True - all validations have passed """

        for validator_name in self.validators:
            validator = validator_name(self._password)
            validator.is_valid()

        return True

    def get_password(self) -> object:
        """ method returns self._password """

        return self._password


class LengthValidator(Validator):
    """ Validator checks if password lenght is min 8 chars"""

    def __init__(self, password):
        self._password = password

    def is_valid(self):
        """ Checks if password length is min 8 chars
        :raise ValidationError
            password length < 8 chars
        :returns bool
           True- password length >= 8 chars"""

        if len(self._password) >= 8:
            return True

        raise ValidationError('Password must contain at least 8 characters. ')


class DigitValidator(Validator):
    """ Validator checks if password contains at least 1 digit"""

    def __init__(self, password):
        self._password = password

    def is_valid(self):
        """ Checks if password contains at least 1 digit
        :raise ValidationError
            no digit in the password
        :returns bool
            True - password has digit(s) """

        if any([letter.isdigit() for letter in self._password]):
            return True

        raise ValidationError('Password must contain at least one number. ')


class SpecialCharValidator(Validator):
    """ Validator checks if password contains at least 1 special character"""

    def __init__(self, password):
        self._password = password

    def is_valid(self):
        """ Checks if password contains at least 1 special character
        :raise ValidationError
            no special character in the password
        :returns bool
            True - password has at least 1 special character """

        if not all([letter.isalnum() for letter in self._password]):
            return True

        raise ValidationError('Password must contain at least 1 special character. ')


class UpperValidator(Validator):
    """ Validator checks if password contains at least 1 upper letter"""

    def __init__(self, password):
        self._password = password

    def is_valid(self):
        """ Checks if password contains at least 1 upper letter
        :raise ValidationError
            no upper letter in the password
        :returns bool
            True - password has at least 1 upper letter """

        if any([letter.isupper() for letter in self._password]):
            return True

        raise ValidationError('Password must contain at least 1 Upper letter. ')


class LowerValidator(Validator):
    """ Validator checks if password contains at least 1 lower letter"""

    def __init__(self, password):
        self._password = password

    def is_valid(self):
        """ Checks if password contains at least 1 lower letter
        :raise ValidationError
            no lower letter in the password
        :returns bool
            True - password has at least 1 lower letter """

        if any([letter.islower() for letter in self._password]):
            return True

        raise ValidationError('Password must contain at least 1 lower letter. ')


class PwnedValidator(Validator):
    """ Validator checks if password has been pwned"""

    def __init__(self, password):
        self._password = password

    def is_valid(self):
        """checks if password (hashed sha1) has benn pwned:
        :raise ValidationError
            password has benn pwned
        :return bool
            True - password not been pwned """

        hashed_pass = self.hash_pass()

        response_text = get(f'https://api.pwnedpasswords.com/range/{hashed_pass[0:5].upper()}') \
            .text.split('\r\n')

        for row in response_text:
            row_splited = row.split(':')
            if hashed_pass[0:5] + row_splited[0] == hashed_pass:
                raise ValidationError('Password has been pwned! ')
        return True

    def hash_pass(self) -> str:
        """Returns hashed self._password"""

        return sha1(self._password.encode('utf-8')).hexdigest().upper()
