import pytest
from requests import get
import requests_mock
from validators import (LengthValidator,
                        DigitValidator,
                        SpecialCharValidator,
                        UpperValidator,
                        LowerValidator,
                        PwnedValidator,
                        ValidationError)


def test_lenght_validator_is_valid_positive():
    validator1 = LengthValidator('aQ1w./I9')  # 8-len
    validator2 = LengthValidator('hj&KąS=+0A')  # 10-len
    assert validator1.is_valid() is True
    assert validator2.is_valid() is True


def test_lenght_validator_is_valid_negative():
    valdiator = LengthValidator('Q1w./I9')  # 7-len

    with pytest.raises(ValidationError) as error:
        valdiator.is_valid()
        assert 'Password must contain at least 8 characters. ' in str(error.value)


def test_digit_validator_positive():
    validator1 = DigitValidator('aQ1w./I9')  # 1,9 - digit
    validator2 = DigitValidator('hj&KąS=+0A')  # 0 - digit
    assert validator1.is_valid() is True
    assert validator2.is_valid() is True


def test_digit_validator_negative():
    valdiator = DigitValidator('asdfghjk')  # no digit

    with pytest.raises(ValidationError) as error:
        valdiator.is_valid()
        assert 'Password must contain at least one number. ' in str(error.value)


def test_special_character_validator_positive():
    validator1 = SpecialCharValidator('aQ1w.I9')  # . special char
    validator2 = SpecialCharValidator('aQ1wI/9')  # / special char
    assert validator1.is_valid() is True
    assert validator2.is_valid() is True


def test_special_character_validator_negative():
    validator = SpecialCharValidator('aQ1wI9')  # no special chars
    with pytest.raises(ValidationError) as error:
        validator.is_valid()
        assert 'Password must contain at least 1 special character. ' in str(error.value)


def test_upper_validator_positive():
    validator1 = UpperValidator('ASDFGHJK')
    validator2 = UpperValidator('asdfghjK')
    assert validator1.is_valid() is True
    assert validator2.is_valid() is True


def test_upper_validator_negative():
    validator = UpperValidator('a1d.f!g`h:"jk')
    with pytest.raises(ValidationError) as error:
        validator.is_valid()
        assert 'Password must contain at least 1 Upper letter. ' in str(error.value)


def test_lower_validator_positive():
    validator1 = LowerValidator('ASDFGHjK')
    validator2 = LowerValidator('asdfghjK')
    assert validator1.is_valid() is True
    assert validator2.is_valid() is True


def test_lower_validator_negative():
    validator = LowerValidator('A1D.F!G`H:"JK')
    with pytest.raises(ValidationError) as error:
        validator.is_valid()
        assert 'Password must contain at least 1 lower letter. ' in str(error.value)


def test_pwned_validator_positive(requests_mock):  # password pwwned
    validator = PwnedValidator('hj&KąS=+0A')
    data = '0077CA954CC79F02509ED44973DD93D21CE:3\r\n950EB9C46987DE5C45730D0F4DA6B2E2BED:2\r' \
           '\n00F626A857CEB9F52485169D8ABDC285085:1 '
    requests_mock.get('https://api.pwnedpasswords.com/range/D8CFD', text=data)
    with pytest.raises(ValidationError) as error:
        validator.is_valid()
        assert 'Password has been pwned! ' in str(error.value)


def test_pwned_validator_negative(requests_mock):  # password not pwned
    validator = PwnedValidator('hj&KąS=+0A')
    data = '0077CA954CC79F02509ED44973DD93D21CE:3\r\n850EB9C46987DE5C45730D0F4DA6B2E2BED:2\r' \
           '\n00F626A857CEB9F52485169D8ABDC285085:1 '
    requests_mock.get('https://api.pwnedpasswords.com/range/D8CFD', text=data)
    assert validator.is_valid() is True
