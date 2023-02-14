## Getting Started

Welcome to the VS Code Java world. Here is a guideline to help you get started to write Java code in Visual Studio Code.

## Folder Structure

The workspace contains two folders by default, where:

- `src`: the folder to maintain sources
- `lib`: the folder to maintain dependencies

Meanwhile, the compiled output files will be generated in the `bin` folder by default.

> If you want to customize the folder structure, open `.vscode/settings.json` and update the related settings there.

## Dependency Management

The `JAVA PROJECTS` view allows you to manage your dependencies. More details can be found [here](https://github.com/microsoft/vscode-java-dependency#manage-dependencies).

sudo apt install openjdk-17-jdk

cd /Users/kamalswami/Documents/ABE ; /usr/bin/env /Library/Java/JavaVirtualMachines/jdk-17.jdk/Contents/Home/bin/java @/var/folders/d3/zq7yjyy57fx797nstk404lk80000gn/T/cp_2zelwrrqgjsfw49xfjt8u6yqa.argfile App 

cd /home/kamal/ABE ; /usr/bin/env /lib/jvm/java-17-openjdk-arm64/bin/java @/home/kamal/ABE/temp.argfile App

cat cp_2zelwrrqgjsfw49xfjt8u6yqa.argfile 
 -XX:+ShowCodeDetailsInExceptionMessages -cp "/Users/kamalswami/Documents/ABE/bin:/Users/kamalswami/Documents/ABE/lib/json-simple-1.1.1.jar:/Users/kamalswami/Documents/ABE/lib/py4j0.10.9.7.jar:/Users/kamalswami/Documents/ABE/lib/jpbc-api-1.2.1.jar:/Users/kamalswami/Documents/ABE/lib/jpbc-plaf-1.2.1.jar"% 

# java server
/usr/bin/env /Library/Java/JavaVirtualMachines/jdk-17.jdk/Contents/Home/bin/java @/var/folders/d3/zq7yjyy57fx797nstk404lk80000gn/T/cp_2zelwrrqgjsfw49xfjt8u6yqa.argfile App

# activate python env
source venv/bin/activate 

# start flask server
cd /Users/kamalswami/Documents/ABE ; python app.py 

# connect to ngrok
cd /Users/kamalswami/Downloads ; ./ngrok http 5000 



# ubuntu 


javac -classpath lib/*:. -d bin -sourcepath . src/*/*.java src/*/policy/*.java src/App.java 

// java /bin/App


sudo apt install virtualenv


virtualenv venv
source venv


pip install -r requirements.txt
python app.py