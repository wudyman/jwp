package javastd;
import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;
import java.util.Scanner;

public class NetTest
{
	public static void main(String[] args)
	{
		try
		{
			//Socket s=new Socket("s1a.time.edu.cn",13);
			Socket s=new Socket("time-a.nist.gov",13);
			try
			{
				InputStream inStream=s.getInputStream();
				Scanner in=new Scanner(inStream);
				while(in.hasNextLine())
				{
					String line=in.nextLine();
					System.out.println(line);
				}
			}
			finally
			{
				s.close();
			}
		}
		catch (IOException e)
		{
			e.printStackTrace();
		}
	}
}