package javabean;

import java.sql.*;

public class DbMysqlBean {
	private Connection conn;
	private String driver;
	private String username;
	private String password;
	private String url;
	
	public DbMysqlBean(){}
	public DbMysqlBean(String driver,String url,String username,String password){
		this.driver=driver;
		this.username=username;
		this.password=password;
		this.url=url;
	}
	public String getDriver() {
		return driver;
	}
	public void setDriver(String driver) {
		this.driver = driver;
	}
	public String getUsername() {
		return username;
	}
	public void setUsername(String username) {
		this.username = username;
	}
	public String getPassword() {
		return password;
	}
	public void setPassword(String password) {
		this.password = password;
	}
	public String getUrl() {
		return url;
	}
	public void setUrl(String url) {
		this.url = url;
	}
	//获得数据库连接
	public Connection getConnection() throws Exception{
		if(conn==null){
			/*JDBC常见错误：
			 * *错误信息：java.lang.ClassNotFoundException: com.mysql.jdbc.Driver
			 * *错误原因：出现这个问题一般是没有引入mysql驱动相关的包。
			 * *解决办法：将mysql-connector-java-5.1.25-bin.jar复制到项目\WebRoot\WEB-INF\lib文件夹下
			 * *或用Build Path将包导进去。
			 * */

			Class.forName(this.driver);
			conn=DriverManager.getConnection(url, username, this.password);
			}
		return conn;
		} 
	//插入记录
	public boolean insert(String sql,Object... args) throws Exception{
		PreparedStatement pstmt=getConnection().prepareStatement(sql);
		for(int i=0;i<args.length;i++){
			pstmt.setObject(i+1, args[i]);
		}
		if(pstmt.executeUpdate()!=1){
			return false;
		}
		return true;
	}
	//执行查询
	public ResultSet query(String sql,Object... args) throws Exception{
		PreparedStatement pstmt=getConnection().prepareStatement(sql);
		for(int i=0;i<args.length;i++){
			pstmt.setObject(i+1, args[i]);
		}
		return pstmt.executeQuery();
	}
	//执行修改
	public void modify(String sql,Object... args) throws Exception{
		PreparedStatement pstmt=getConnection().prepareStatement(sql);
		for(int i=0;i<args.length;i++){
			pstmt.setObject(i+1, args[i]);
		}
		pstmt.executeUpdate();
		pstmt.close();
	}
	//关闭数据库连接的方法
	public void closeConn() throws Exception{
		if(conn!=null&&!conn.isClosed()){
			conn.close();
		}
	}
	
	public static void main(String[] args)
	{
		try{
			Class.forName("com.mysql.jdbc.Driver");
			System.out.println("Success loading Mysql Driver");
		}
		catch (Exception e){
			System.out.println("Error loading Mysql Driver!");
			e.printStackTrace();
		}
	}
}