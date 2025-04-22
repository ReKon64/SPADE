class Test:
    _extensions = {}
    def __init__(self, var):  # Fixed the method name (double underscores)
        self.var = var
        # Missing code to apply extensions to instance
        for name, func in self.__class__._extensions.items():
            setattr(self, name, func.__get__(self, self.__class__))
   
    def output(self):
        print(f"{self.var}")
        
    @classmethod
    def extend(cls, func):
        """Decorator to register extension methods"""
        cls._extensions[func.__name__] = func
        return func

@Test.extend
def alternate(self):
    print(f"Alternate {self.var}")
    print(f"Now back again")
    self.output()

lol = Test("hahaha")
lol.output()  # Fixed: Use the instance to call the instance method
lol.alternate()  # Added to test the extended method