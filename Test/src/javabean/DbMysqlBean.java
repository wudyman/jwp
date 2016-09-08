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
	//������ݿ�����
	public Connection getConnection() throws Exception{
		if(conn==null){
			/*JDBC��������
			 * *������Ϣ��java.lang.ClassNotFoundException: com.mysql.jdbc.Driver
			 * *����ԭ�򣺳����������һ����û������mysql������صİ���
			 * *����취����mysql-connector-java-5.1.25-bin.jar���Ƶ���Ŀ\WebRoot\WEB-INF\lib�ļ�����
			 * *����Build Path��������ȥ��
			 * */

			Class.forName(this.driver);
			conn=DriverManager.getConnection(url, username, this.password);
			}
		return conn;
		} 
	//�����¼
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
	//ִ�в�ѯ
	public ResultSet query(String sql,Object... args) throws Exception{
		PreparedStatement pstmt=getConnection().prepareStatement(sql);
		for(int i=0;i<args.length;i++){
			pstmt.setObject(i+1, args[i]);
		}
		return pstmt.executeQuery();
	}
	//ִ���޸�
	public void modify(String sql,Object... args) throws Exception{
		PreparedStatement pstmt=getConnection().prepareStatement(sql);
		for(int i=0;i<args.length;i++){
			pstmt.setObject(i+1, args[i]);
		}
		pstmt.executeUpdate();
		pstmt.close();
	}
	//�ر����ݿ����ӵķ���
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