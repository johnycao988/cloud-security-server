function submitLogin() {
	
	alert("login");
	
	var name = $("#userId").val();
	
	if (name.length <= 0){
		$("#msgName").html("Username can't be empty!");
		return false;	 
	}
	
	var pass = $("#userPwd").val();
	if (pass.length <= 0){
		$("#msgName").html("Password can't be empty!");
		return false;	 
	}
	
	return false;
	//"action="${pageContext.request.contextPath}/rest/user/pageLogin
	// 提交到后台进行验证
	$.ajax({
		type : "POST",// 指定是post还是get,当然此处要提交,当然就要用post了
		cache : "false",// 默认: true,dataType为script时默认为false) jQuery 1.2 新功能，设置为
						// false 将不会从浏览器缓存中加载请求信息。
		url : "loginServlet",// 发送请求的地址。
		data : "username=" + name + "&password=" + pass,// 发送到服务器的数据
		dataType : "text",// 返回纯文本字符串 timeout:20000,// 设置请求超时时间（毫秒）。
		error : function() {// 请求失败时调用函数。
			$("#msg").html("请求失败!");
		},
		success : // 请求成功后回调函数。
		function(message) {
			$("#msg").html(message);
		}
	});
	
	return false;
}
