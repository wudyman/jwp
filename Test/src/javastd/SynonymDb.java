package javastd;

import java.sql.*;
public class SynonymDb
{
	public static final String driver="com.mysql.jdbc.Driver";
	public static final String urlDB="jdbc:mysql://localhost:3306/synonyms_db?useSSL=true";
	public static final String userName="root";
	public static final String passWord="123456";
	
	public static final String sqlCreatTable="create table han_synonyms(id int unsigned not null auto_increment primary key,word1 varchar(8) not null,word2 varchar(8) not null,word3 varchar(8) not null)";
	public static final String sqlInsert="insert han_synonyms values(NULL,?,?,?)";
	public static final String sqlSelect="select * from han_synonyms";
	public static final String tableName="han_synonyms";
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
			
			DatabaseMetaData metaData=connect.getMetaData();
			String[] type={"TABLE"};
			ResultSet rs=metaData.getTables(null, null, tableName, type); 
			boolean flag=rs.next();
			PreparedStatement pstmt=null;
			
			if(!flag)
			{
			pstmt=connect.prepareStatement(sqlCreatTable);
			pstmt.executeUpdate();
			}
			
			pstmt=connect.prepareStatement(sqlInsert);
			//pstmt.setInt(1, null);
			pstmt.setString(1, "æ⁄…•");
			pstmt.setString(2, "”Ù√∆");
			pstmt.setString(3, "µÕ¬‰");
			pstmt.executeUpdate();
			/*
			pstmt.setInt(1, 5);
			pstmt.setString(2, "ø∆±»");
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
			rs=pstmt.executeQuery();
			
			while(rs.next()){
				System.out.println(rs.getString("word1"));
			}
		}
		catch(Exception e){
			System.out.println("get data error!");
			e.printStackTrace();
		}
	}
	
}