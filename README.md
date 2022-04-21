##This script checks if your password contains at least:
1. 8 chars lenght
2. One upper letter
3. One lower letter
4. One digit
5. One special character..

..and finally if the password has been pwned

App reads file 'passwords.txt'. The file has to contain one password each line.
In case of password not pass some test it raises ValidationError ang log it to infos.log file.

Password that passed all tests is written to file 'checked.txt' (one password each line)