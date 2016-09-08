<%@ page language="java" contentType="text/html; charset=utf-8"
    pageEncoding="utf-8"%>
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8">
<script src="js/jquery-3.1.0.min.js"></script>
<!--<script src="http://apps.bdimg.com/libs/jquery/2.1.1/jquery.js"></script>-->
<title>Convert Page</title>
</head>
<body>
<p class="p medium">请输入要进行同义词转换的文章：</p>
<textarea name="src" id="src" cols="80" rows="6" style="width:99%;height:120px;"></textarea>
<p class="p tcenter">
<input onclick="doConvert()" type="button" value="转换" name="encode" class="search-submit">
</p>
<p class="p medium">转换文章结果：</p>
<textarea name="dest" id="dest" cols="80" rows="6" style="width:99%;height:120px;"></textarea>

<script>
function convert(src)
{
	//document.getElementById('dest').value="test";
	var MaxWordSize=4;
	var wordIndex=0;
	var wordSize=2;
	var textLength=src.length;
	var temp="";
	for(wordIndex=0;wordIndex<textLength;wordIndex++)
		{
		for(wordSize=2;wordSize<=MaxWordSize;wordSize++)
			{
			temp+=src.substring(wordIndex,wordIndex+wordSize);
			temp+=',';
			}
		}
	//var temp=src.substring(wordIndex,wordSize);
	return temp;
}
function postText(text,URL)
{

	 var temp = document.createElement("form");
	  temp.action = URL;
	  temp.method = "post";
	  //temp.charset= "utf-8";
	  //temp.accept-charset="utf-8"; 
	  //temp.onsubmit=document.charset='utf-8';
	  
	  temp.style.display = "none";
	  
	  var opt = document.createElement("textarea");
	  opt.name = "tt";
	  opt.value = text;
	  //alert(opt.name);
	  temp.appendChild(opt);

	  document.body.appendChild(temp);
	  temp.submit();
	  return temp;
	  
}
function postTextAjax(text,url)
{
	var result;
	$.ajax({
		  type: 'POST',
		  url: url,
		  data: 
		  {
		  tt: text
		  },
		  dataType: 'text',
		  async:false,
		  success:function(returnData){
			      //document.getElementById('dest').value=returnData;
				 result=returnData;				 
		  },
		  error:function()
		  {
			  alert("fail");
		  }
		});
	return result;
}
function doConvert()
{
	var src=document.getElementById('src').value;
	//var dst=src;//convert(src);
	// postText(dst,'getText.jsp');
	//postText(dst,'convert_text');
	//postTextAjax(dst,'getText.jsp');
	var dst=postTextAjax(src,'convert_text');
	document.getElementById('dest').value=dst;
}

</script>

</body>
</html>