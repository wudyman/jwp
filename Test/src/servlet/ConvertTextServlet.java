package servlet;

import java.io.IOException;
import java.io.PrintWriter;
import java.sql.ResultSet;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import javabean.DbMysqlBean;

/**
 * Servlet implementation class ConvertTextServlet
 */
///@WebServlet("/ConvertTextServlet")
public class ConvertTextServlet extends HttpServlet {
	private static final long serialVersionUID = 1L;
	public static final String driver="com.mysql.jdbc.Driver";
	public static final String urlDB="jdbc:mysql://localhost:3306/synonyms_db?useSSL=true";
	public static final String rootName="root";
	public static final String rootPassWord="123456";
	
	public static final int MaxWordSize=4;
	private int wordIndex=0;
	private int wordSize=2;
	private String word="";
	private String returnText="";
	//public static int textLength=src.length;
	//var temp="";
       
    /**
     * @see HttpServlet#HttpServlet()
     */
    public ConvertTextServlet() {
        super();
        // TODO Auto-generated constructor stub
    }

	@Override
	public void service(HttpServletRequest request, HttpServletResponse response)
			throws ServletException, IOException {
		String errMsg="";
		RequestDispatcher rd;
        //上面那个request降落在这里
		//String text = new String((request.getParameter("tt")).getBytes("ISO-8859-1"),"UTF-8");
		String text = request.getParameter("tt");
		System.out.println("text:"+text);
		try{
			/*Servlet只是处理控制逻辑，简单说就是起到一个分配任务的作用
			 * *而真正处理业务逻辑的是Model层，也就是Javabean
			 * *在这里，Servlet调用了DbDao，创建实例，并将请求所带的参数（）
			 * */ 
			DbMysqlBean dd=new DbMysqlBean(driver,urlDB,rootName,rootPassWord);
			ResultSet rs=null;			
			for(wordIndex=0;wordIndex<text.length()-MaxWordSize;)
			{
				for(wordSize=2;wordSize<=MaxWordSize;wordSize++)
				{
					rs=null;
					word=text.substring(wordIndex, wordIndex+wordSize);
					//System.out.println("now query:"+word);
					rs=dd.query("select * from han_synonyms where word1=? or word2=? or word3=?",word,word,word);
					if(rs.next())
					{
						if(rs.getString("word1").equals(word))
						{
							//System.out.println("word1 match");
							word=rs.getString("word2");
						}
						else if(rs.getString("word2").equals(word))
						{
							//System.out.println("word2 match");
							if(rs.getString("word3").equals("无"))
							word=rs.getString("word1");
							else
							word=rs.getString("word3");
						}
						else if(rs.getString("word3").equals(word))
						{
							//System.out.println("word3 match");
							word=rs.getString("word1");
						}
						else
							System.out.println("no match");
						
						returnText+=word;
						wordIndex=wordIndex+wordSize;
						break;
					}
				}
				if(wordSize>MaxWordSize)
				{
				//wordSize=MaxWordSize;
				returnText+=text.substring(wordIndex,wordIndex+1);
				wordIndex++;
				}
				wordSize=2;
			}
			returnText+=text.substring(wordIndex,text.length());
		    //request.setAttribute("convertText", returnText);
		    //rd=request.getRequestDispatcher("/welcome.jsp");
		    //rd.forward(request, response);
		 
		    //String jsonStr = "{'info':'"+name+"'}";
			//response.setContentType("text/html;charset=utf-8");
		    response.setCharacterEncoding("utf-8");
		    PrintWriter out = response.getWriter();
		    out.println(returnText);
	    }
		catch(Exception e){
			e.printStackTrace();
		}
		
		if(errMsg!=null&&!errMsg.equals("")){
			System.out.println("no data");
		}
	}
	
	/**
	 * @see HttpServlet#doGet(HttpServletRequest request, HttpServletResponse response)
	 */
	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		// TODO Auto-generated method stub
		response.getWriter().append("Served at: ").append(request.getContextPath());
	}

	/**
	 * @see HttpServlet#doPost(HttpServletRequest request, HttpServletResponse response)
	 */
	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		// TODO Auto-generated method stub
		System.out.println("have called");
		doGet(request, response);
	}

}
