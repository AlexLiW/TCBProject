package main;

import java.security.MessageDigest;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;


import org.apache.tomcat.util.codec.binary.Base64;
import org.json.JSONObject;
import com.jeedsoft.common.basic.util.JsonUtil;


public class DoAuthGenerator {
	public String getCheckCode(String idno,String code,String timestamp,String AES_KEY) 
	{			
		try {
			String checkCode = hash256(code+idno+timestamp);
					
			return checkCode;
		}
		catch(Exception ex) {
			return ex.getMessage();
		}
		
	}
	
	
	//ASE-128 ECB 加密
	public String Encrypt(String sSrc, String sKey){
		try {
			if (sKey == null) {
	            return null;
	        }
	        /*if (sKey.length() != 16) {
	            return null;
	        }*/
	        byte[] raw = sKey.getBytes("utf-8");
	        SecretKeySpec skeySpec = new SecretKeySpec(raw, "AES");
	        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");//"算法/模式/补码方式"
	        cipher.init(Cipher.ENCRYPT_MODE, skeySpec);
	        byte[] encrypted = cipher.doFinal(sSrc.getBytes("utf-8"));

	        return new Base64().encodeToString(encrypted);//此处使用BASE64做转码功能，同时能起到2次加密的作用。
		}
		catch(Exception ex) {
			ex.printStackTrace();
			return null;
		}
    }
	
	//加密
	public String getAuth(String idno,String code,String timestamp,String AES_KEY) 
	{			
		try {
			String checkCode = hash256(code+idno+timestamp);
			JSONObject obj = new JSONObject();		
			obj.put("timestamp", timestamp);
			obj.put("checkCode", checkCode);
			obj.put("code", code);
			obj.put("idno", idno);
			String objString = obj.toString().replace("\""+timestamp+"\"", timestamp);
			String AES_KEYs = AES_KEY.substring(0,32);
			String IVs = AES_KEY.substring(AES_KEY.length()-32,AES_KEY.length());
			String rstData = pkcs7padding(objString);	
			String passwordEnc = AESencrypt(rstData,AES_KEYs,IVs);
			return passwordEnc;
		}
		catch(Exception ex) {
			ex.printStackTrace();
			System.out.println(ex);	
			return ex.getMessage();
		}
		
	}
	
	//AES PKCS7Padding 加密
	 public static byte[] toByteArray(String hexString) {
	        hexString = hexString.toLowerCase();
	        final byte[] byteArray = new byte[hexString.length() >> 1];
	        int index = 0;
	        for (int i = 0; i < hexString.length(); i++) {
	            if (index  > hexString.length() - 1)
	                return byteArray;
	            byte highDit = (byte) (Character.digit(hexString.charAt(index), 16) & 0xFF);
	            byte lowDit = (byte) (Character.digit(hexString.charAt(index + 1), 16) & 0xFF);
	            byteArray[i] = (byte) (highDit << 4 | lowDit);
	            index += 2;
	        }
	        System.out.println(byteArray.length);
	        return byteArray;
	    }
	
	 public String AESencrypt(String Data,String aKey,String aiv) {
	        try {
	            byte[] iv = toByteArray(aiv);//因为要求IV为16byte，而此处aiv串为32位字符串，所以将32位字符串转为16byte
	            Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
	            int blockSize = cipher.getBlockSize();
	            byte[] dataBytes = Data.getBytes();
	            int plaintextLength = dataBytes.length;
	            if (plaintextLength % blockSize != 0) {
	                plaintextLength = plaintextLength + (blockSize - (plaintextLength % blockSize));
	            }
	            byte[] plaintext = new byte[plaintextLength];
	            System.arraycopy(dataBytes, 0, plaintext, 0, dataBytes.length);
		        SecretKeySpec keyspec = new SecretKeySpec(aKey.getBytes("utf-8"), "AES");
	            IvParameterSpec ivspec = new IvParameterSpec(iv);
	            cipher.init(Cipher.ENCRYPT_MODE, keyspec, ivspec);
	            byte[] encrypted = cipher.doFinal(plaintext);
	            
	            return new Base64().encodeToString(encrypted);

	        } catch (Exception e) {
	            e.printStackTrace();
	            return null;
	        }
	    }
	
	public static String pkcs7padding(String data) {
        int bs = 16;
        int padding = bs - (data.length() % bs);
        String padding_text = "";
        for (int i = 0; i < padding; i++) {
            padding_text += (char)padding;
        }
        return data+padding_text;
    }
	
	
	//AES PKCS7Padding 解密
	public String AESdecrypt(String AESKey,String encryptedData) {
        try {
        	String akey = AESKey.substring(0,32);
        	String aiv = AESKey.substring(AESKey.length()-32,AESKey.length());
            byte[] encrypted1 = new Base64().decode(encryptedData);
            byte[] iv = toByteArray(aiv);
            Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
            SecretKeySpec keyspec = new SecretKeySpec(akey.getBytes("utf-8"), "AES");
            IvParameterSpec ivspec = new IvParameterSpec(iv);
            cipher.init(Cipher.DECRYPT_MODE, keyspec, ivspec);
            byte[] original = cipher.doFinal(encrypted1);
            String originalString = new String(original);
            System.out.println(originalString.trim());
            JSONObject originalStr = new JSONObject(originalString);
            String code = JsonUtil.getString(originalStr, "code", "");
			String idno = JsonUtil.getString(originalStr, "idno", "");
			String timestamp = JsonUtil.getString(originalStr, "timestamp", "");
			String checkCode = JsonUtil.getString(originalStr, "checkCode", "");
			
			String hashcheckCode = hash256(code+idno+timestamp);
			if(hashcheckCode.equals(checkCode)) {
				System.out.println(idno);
			}
            return originalString.trim();
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
	
	
	
			
	// ASE-128 ECB 解密 
		private String Decrypt(String sSrc, String sKey){
	        try {
	            // 
	            if (sKey == null) {
	                return null;
	            }
	            // 
	            if (sKey.length() != 16) {
	                return null;
	            }
	            byte[] raw = sKey.getBytes("utf-8");
	            SecretKeySpec skeySpec = new SecretKeySpec(raw, "AES");
	            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
	            cipher.init(Cipher.DECRYPT_MODE, skeySpec);
	            byte[] encrypted1 = new Base64().decode(sSrc);//
	            try {
	                byte[] original = cipher.doFinal(encrypted1);
	                String originalString = new String(original,"utf-8");
	                return originalString;
	            } catch (Exception e) {
	                return null;
	            }
	        } catch (Exception ex) {
	            return null;
	        }
	    }
		
		//Sha256 加密
		private String hash256(String data) {
	    	try {
	    		MessageDigest md = MessageDigest.getInstance("SHA-256");
	            md.update(data.getBytes());
	            return parseByte2HexStr(md.digest());
	    	}
	    	catch (Exception ex){
	    		return null;
	    	}       
	    }
		
		//Base 64 to Hex String
		private String parseByte2HexStr(byte buf[]) {  
	    	try {
	    		StringBuffer sb = new StringBuffer();  
	            for (int i = 0; i < buf.length; i++) {  
	                    String hex = Integer.toHexString(buf[i] & 0xFF);  
	                    if (hex.length() == 1) {  
	                            hex = '0' + hex;  
	                    }  
	                    sb.append(hex.toUpperCase());  
	            }  
	            return sb.toString(); 
	    	}
	    	catch(Exception ex) {
	    		return null;
	    	}        
	    }
		
	    //Hex String to Base64
		private String parseHexStr2Byte(String hexStr) {  
	    	try {
	    		if (hexStr.length() < 1)  
	                return null;  
	    		byte[] result = new byte[hexStr.length()/2];  
	        	for (int i = 0;i< hexStr.length()/2; i++) {  
	                int high = Integer.parseInt(hexStr.substring(i*2, i*2+1), 16);  
	                int low = Integer.parseInt(hexStr.substring(i*2+1, i*2+2), 16);  
	                result[i] = (byte) (high * 16 + low);  
	        	}  
	        	return  new Base64().encodeToString(result);
	    	}
	    	catch(Exception ex) {
	    		return null;
	    	}
	    }
		
		//取得當前eunix timestamp
		String getNowTimeStamp() {
	        long time = System.currentTimeMillis();
	        String nowTimeStamp = String.valueOf(time);
	        return nowTimeStamp;
	    }
		
		//unix timestamp 轉換 Date
		private String TimeStamp2Date(String timestampString) {
			try {
				String formats= "yyyy-MM-dd HH:mm:ss.SSS";
		        Long timestamp = Long.parseLong(timestampString);
		        String date = new SimpleDateFormat(formats, Locale.TAIWAN).format(new Date(timestamp));
		        return date;
			}
			catch(Exception ex) {
	    		return null;
	    	}   	
	    }
		 
		//取得16亂數
		String getRandom16Key() {
			int z;
		    StringBuilder sb = new StringBuilder();
		    int i;
		    for (i = 0; i < 16; i++) {
		      z = (int) ((Math.random() * 7) % 3);
		 
		      if (z == 1) { // 放數字
		        sb.append((int) ((Math.random() * 10)));
		      } else if (z == 2) { // 放大寫英文
		        sb.append((char) (((Math.random() * 26) + 65)));
		      } else {// 放小寫英文
		        sb.append(((char) ((Math.random() * 26) + 97)));
		      }
		    }
		    return sb.toString(); 
		}
		
		//取得AES加密用金鑰
		String getAESkey(String idno,String randomkey) {
			String AESkey = randomkey+hash256(idno.substring(3,8)+idno.substring(0,3)+idno.substring(8,10));
			return AESkey;
		}
}
