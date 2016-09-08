package servlet;
import java.io.IOException;
import java.sql.*;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javabean.*;

public class LoginServlet extends HttpServlet {
	public static final String driver="com.mysql.jdbc.Driver";
	public static final String urlDB="jdbc:mysql://localhost:3306/samp_db?useSSL=true";
	public static final String rootName="root";
	public static final String rootPassWord="123456";

	public LoginServlet() {
	        super();
	        // TODO Auto-generated constructor stub
	    }
	 
	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		// TODO Auto-generated method stub
		response.getWriter().append("Served at: ").append(request.getContextPath());
		
	}

	@Override
	public void service(HttpServletRequest request, HttpServletResponse response)
			throws ServletException, IOException {
		String errMsg="";
		RequestDispatcher rd;
        //上面那个request降落在这里
		String username=request.getParameter("username");
		String password=request.getParameter("password");
		//response.getWriter().append("username: ").append(username);
		//response.getWriter().append("password: ").append(password);
		try{
			/*Servlet只是处理控制逻辑，简单说就是起到一个分配任务的作用
			 * *而真正处理业务逻辑的是Model层，也就是Javabean
			 * *在这里，Servlet调用了DbDao，创建实例，并将请求所带的参数（）
			 * */ 
			DbMysqlBean dd=new DbMysqlBean(driver,urlDB,rootName,rootPassWord);
			ResultSet rs=dd.query("select passwd from user_table where username=?", username);
			if(rs.next()){
				if(rs.getString("passwd").equals(password)){
					HttpSession session=request.getSession(true);
					session.setAttribute("name", username);
					rd=request.getRequestDispatcher("/welcome.jsp");
					rd.forward(request, response);
				}
				else{
					errMsg+="您输入的用户名或密码不对。";
				}			
			}
			else{
				errMsg+="用户名不存在。";
			}
		}
		catch(Exception e){
			e.printStackTrace();
		}
		
		if(errMsg!=null&&!errMsg.equals("")){
			rd=request.getRequestDispatcher("/login.jsp");
			request.setAttribute("err", errMsg);
			rd.forward(request, response);
		}
	}
	
}