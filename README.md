
## Folder Structure

- `src`: the folder to maintain sources
- `lib`: the folder to maintain dependencies
- `bin`: the folder to maintain class files


# ubuntu 


## install jdk
```sudo apt install openjdk-17-jdk```

## compile application
```javac -cp lib/jpbc-api-1.2.1.jar:lib/jpbc-plaf-1.2.1.jar:lib/json-simple-1.1.1.jar:lib/py4j0.10.9.7.jar -d bin -sourcepath . src/*/*.java src/*/policy/*.java src/App.java ```


## start getway server
```java -cp lib/jpbc-api-1.2.1.jar:lib/jpbc-plaf-1.2.1.jar:lib/json-simple-1.1.1.jar:lib/py4j0.10.9.7.jar:bin/ App```


## create virtual env for python
```sudo apt install virtualenv```
```virtualenv venv```

## activate venv
```source venv```

## install requirements
```pip install -r requirements.txt```

### ngrok
```ngrok http 5000 ```

## start flask servers
```python app.py```

# flask application
## paths
<ul>
<li>/</li>
<li>/encrypt</li>
<li>/encryption/download</li>
<li>/decrypt</li>
<li>/decryption/download</li>
</ul>


# java application
<ul>
<li>setup</li>
<li>keygen</li>
<li>enc</li>
<li>dec</li>
</ul>



# cpp and python
 ```gcc -I/opt/homebrew/include/glib-2.0/ -I/opt/homebrew//Cellar/glib/2.76.1/lib/glib-2.0/include/ -I/opt/homebrew/Cellar/openssl@3/3.1.0/include/ -I/opt/homebrew/Cellar/openssl@3/3.1.0/include/openssl/ -fPIC -shared -o app.so app.c -L. -lgmp -lpbc -lcrypto `pkg-config --cflags --libs glib-2.0` ```


 ```python app2.py ```