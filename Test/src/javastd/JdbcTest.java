package javastd;

import java.sql.*;
public class JdbcTest
{
	public static final String driver="com.mysql.jdbc.Driver";
	public static final String urlDB="jdbc:mysql://localhost:3306/samp_db?useSSL=true";
	public static final String userName="root";
	public static final String passWord="123456";
	
	public static final String sqlInsert="insert Students values(?,?,?,?,?)";
	public static final String sqlSelect="select * from Students";
	public static void main(String[] args)
	{
		System.out.println("this is JdbcTest main");
		try{
			Class.forName(driver);
			System.out.println("Success loading Mysql Driver");
		}
		catch (Exception e){
			System.out.println("Error loading Mysql Driver!");
			e.printStackTrace();
		}
		
		try{
			Connection connect=DriverManager.getConnection(
					urlDB,userName,passWord);
			System.out.println("Success connect Mysql server!");
			PreparedStatement pstmt=connect.prepareStatement(sqlInsert);
			/*
			pstmt.setInt(1, 3);
			pstmt.setString(2, "micky");
			pstmt.setString(3, "fema");
			pstmt.setInt(4, 16);
			pstmt.setString(5, "333333");
			pstmt.executeUpdate();
			
			pstmt.setInt(1, 4);
			pstmt.setString(2, "luke");
			pstmt.setString(3, "male");
			pstmt.setInt(4, 14);
			pstmt.setString(5, "4444");
			pstmt.executeUpdate();
			*/
			
			pstmt=connect.prepareStatement(sqlSelect);
			ResultSet rs=pstmt.executeQuery();
			
			while(rs.next()){
				System.out.println(rs.getString("name"));
			}
		}
		catch(Exception e){
			System.out.println("get data error!");
			e.printStackTrace();
		}
	}
}