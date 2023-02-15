import CPABE.Cpabe;
import java.io.File;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import py4j.GatewayServer;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.*;
import java.io.FileReader;

public class App {
    // static String dir = "/Users/kamalswami/Documents/ABE/.dir";
    static String dir = "/home/azureuser/ABE/.dir";

    static String files_dir = dir + "/.files";

    static String pubfile = dir + "/pub_key";
    static String mskfile = dir + "/master_key";
    static String prvfile = dir + "/prv_key";

    static String user_attribute = "";
    static ArrayList<String> file_attributes = new ArrayList<String>();
    static Cpabe ABE = new Cpabe();
    static String policy = "";

    public static void main(String[] args) throws Exception {
        GatewayServer gatewayServer = new GatewayServer(new App());
        gatewayServer.start();
        System.out.println("Gateway Server Started");
    }

    public static void setup() throws ClassNotFoundException, IOException {
        ABE.setup(pubfile, mskfile);
    }

    public static void keygen() throws NoSuchAlgorithmException, IOException, ParseException {
        JSONParser jp = new JSONParser();
        JSONObject o = (JSONObject) jp.parse(new FileReader(dir+"/attribute.json"));
        user_attribute="id:"+o.get("id")+" designation:"+o.get("designation")+" department:"+o.get("department");
        ABE.keygen(pubfile, prvfile, mskfile, user_attribute);
    }

    public static String enc() throws Exception {
        file_attributes.clear();
        File folder = new File(files_dir);
        File[] listOfFiles = folder.listFiles();
        for (int i = 0; i < listOfFiles.length; i++) {
            if (listOfFiles[i].isFile()) {
                String str = listOfFiles[i].getName().toString();
                int index = str.length() - 1;
                while (str.charAt(index) != '.')
                    index--;

                file_attributes.add("object-name:" + listOfFiles[i].getName() + " " + "object-size:"
                        + listOfFiles[i].length() + "B object-type:" + str.substring(index + 1));
            }
        }
        policy="";
        JSONParser jp = new JSONParser();
        JSONObject o = (JSONObject) jp.parse(new FileReader(dir+"/policies.json"));

        JSONArray jsonArray = (JSONArray) o.get("policies");
        
        for(int i=0; i<jsonArray.size(); i++){
            // println(jsonArray.get(i).toString().split(","));
            String row = "";
        
            String[] p = jsonArray.get(i).toString().split(",");
            for(int j=0; j<p.length; j++){
                String attrs = p[j];
                if(j==0)attrs=attrs.substring(1, attrs.length());
                if(j==p.length-1)attrs=attrs.substring(0,attrs.length()-1);
                String c = ""+attrs.substring(0,1);
                attrs=attrs.replaceAll(c, "");
                if(row=="")row+=attrs;
                else row+=" "+attrs;
            }
            if(p.length>1)row+= " "+p.length+"of"+p.length;
            if(policy=="")policy+=row;
            else policy+= " "+row;
        }

        if(jsonArray.size()!=1)policy+=" 1of"+jsonArray.size();

        println("//start to enc");
        for (int i = 0; i < file_attributes.size(); i++) {
            String new_policy = ABE.simplify_policy(policy, file_attributes.get(i));
            println(new_policy);
            ABE.enc(pubfile, new_policy, files_dir + "/" + file_attributes.get(i).split(" ")[0].split(":")[1],
                    dir + "/encrypted/" + file_attributes.get(i).split(" ")[0].split(":")[1] + ".cpabe");
        }
        println("//end to enc");
        return policy;
    }

    public static void dec() throws Exception{
        println("//start to dec");
		for(int i=0; i<file_attributes.size(); i++) {
			ABE.dec(pubfile, prvfile, dir+"/encrypted/"+file_attributes.get(i).split(" ")[0].split(":")[1]+".cpabe", dir+"/decrypted/"+file_attributes.get(i).split(" ")[0].split(":")[1]);
		}
		println("//end to dec");
    }

    private static void println(Object o) {
        System.out.println(o);
    }

}
