import org.apache.catalina.mbeans.SparseUserDatabaseMBean;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;

public class Loop {
    public static void main(String[] args) {
        Key key = new Key("www.baidu.com");
        System.out.println(key.hex() + "\n" + key.base64());
    }

}

class Key{
    public String key;

    public Key(String key) {
        this.key = key;
    }
    public String hex(){
        return Hex.toHexString(key.getBytes());
    }

    public String base64(){
        return Base64.toBase64String(key.getBytes());
    }
}