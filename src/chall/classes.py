import os
import time

class SA_seed():
    def __init__(self, level):
        self.level = level
        self.seed = os.urandom(4)
        self.generated = time.time()

    def is_valid(self):
        return time.time() - self.generated < 600
    
    def __str__(self):
        return "Seed: {}, Level: {}, Generated: {}, Valid: {}".format(self.seed, self.level, self.generated, self.is_valid())

    def __repr__(self):
        return "Seed: {}, Level: {}, Generated: {}, Valid: {}".format(self.seed, self.level, self.generated, self.is_valid())