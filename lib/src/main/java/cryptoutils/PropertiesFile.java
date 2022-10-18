package cryptoutils;

import java.io.IOException;
import java.util.Properties;

public class PropertiesFile {
    public static void main(String[] args) throws IOException {
        var properties = new Properties();
        properties.load(PropertiesFile.class.getResourceAsStream("/properties"));

        var ca1Attr1 = properties.get("cat1.attr2");

        System.out.println("cat1.attr2: " + ca1Attr1);
    }
}
