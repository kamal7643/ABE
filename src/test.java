
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.*;

import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;

public class test {
    static String dir = System.getProperty("user.dir")+"/.dir";
    public static void main(String[] args) throws FileNotFoundException, IOException, ParseException{
        JSONParser jp = new JSONParser();
        String user_attribute="";
        JSONObject o = (JSONObject) jp.parse(new FileReader(dir+"/attribute.json"));
        JSONObject userattr = (JSONObject)o.get("user-attribute");
        JSONObject envattr = (JSONObject)o.get("env-attribute");
        user_attribute="id:"+userattr.get("id")+" designation:"+userattr.get("designation")+" department:"+userattr.get("department");
        user_attribute+="env-time:"+envattr.get("time")+" env-day:"+envattr.get("day")+" env-month:"+envattr.get("month")+ " env-year:"+envattr.get("year");
        System.out.print(user_attribute);
    }
}
