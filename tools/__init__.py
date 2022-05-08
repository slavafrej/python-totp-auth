import random


class Passgen:
    def __init__(self, length, mode):
        """
        :param length: 8 - unlimited
        :param mode: 1 - Low; 2 - Middle; 3 - Strength
        """
        import random
        self.length = length
        self.mode = mode
        self.password = ""

    def generate(self):
        if self.mode == 1:
            for i in range(self.length):
                self.password += random.choice(list('1234567890abcdefghigklmnopqrstuvyxwz'))
        if self.mode == 2:
            for i in range(self.length):
                self.password += random.choice(list('1234567890abcdefghigklmnopqrstuvyxwzABCDEFGHIGKLMNOPQRSTUVYXWZ'))
        if self.mode == 3:
            for i in range(self.length):
                self.password += random.choice(list('1234567890abcdefghigklmnopqrstuvyxwzABCDEFGHIGKLMNOPQRSTUVYXWZ!"#$%&()*+,-./:;<=>?@[\]^_`{|}~'))
        return self.password

