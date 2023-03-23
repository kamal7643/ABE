import ctypes

# Load the shared library
myclass_lib = ctypes.cdll.LoadLibrary('./cpabe_2.so')

# Define the C++ class interface using ctypes
class MyClass(ctypes.Structure):
    _fields_ = [
        ('_opaque', ctypes.c_void_p)
    ]

# Define the constructor function
def MyClass_new(x):
    obj = MyClass()
    # obj._opaque = myclass_lib.MyClass_new(x)
    return obj

# Define the method getX
def MyClass_getX(self):
    return myclass_lib.MyClass_getX(self._opaque)

# Add the method to the class
MyClass.getX = MyClass_getX

# Create an object of the C++ class
obj = MyClass_new(42)

# Call the getX method
print(obj.getX()) # Output: 42
