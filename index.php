<!DOCTYPE html>
<html>
<head>
    <title>JGB crud</title>
    <link rel="stylesheet" type="text/css" href="./styles.css" />
</head>
<body>

<?php

#########
require("db_connect.php");
require("functions.php");


if(isset($_POST['logout'])){
	logoutUser(true);
		header("Refresh:0");
	return;
	
}

if(isset($_POST['submit_login'])) {
	
	$formpassword = $_POST['password'];	
	$user = sqlSelect ($mysqli, 'SELECT id, username, admin, password FROM users WHERE username = ?', 's', $_POST['username']);
	if($user[0]['id'] || $user[0]['password']) {
		if(password_verify($formpassword, $user[0]['password'])) {

			$validuser = $user[0]['username'];
			$_SESSION['loggedin'] = TRUE;
			$_SESSION['username'] = $validuser;
			$_SESSION['admin'] = $user[0]['admin'];
			$_SESSION['id'] = $user[0]['id'];
				header("Refresh:1");
			
			} else {
				echo "<p>Username en/of password onjuist/onbekend.</p>";
			}
    	}else{
			$err_message[] = "Found nothing";
		}
	
} elseif(isset($_SESSION['loggedin'])) {
	echo "<p><div class=\"loggedintext\">Hello {$_SESSION['username']}, you are logged in. </div></p>";
?>
<hr>
	<form method="POST" action="index.php" id="actionMenu">
        <input class="styledbutton" type="submit" name="Create" value="Create" >  
        <input class="styledbutton" type="submit" name="Update" value="Update" > 
        <input class="styledbutton" type="submit" name="Delete" value="Delete" >  
		<input class="logoutbutton" type="submit" name='logout' value='logout' >
	</form>
	<hr>
<?php

############## Create ########################

if(isset($_POST['Create']) OR isset($_POST['submit_create'])){

	if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST["submit_create"])) {
			#handle admin checkbox
			$admin = (!isset($_POST['admin'])) ? 0 : 1;

			$password = $_POST["password"]; //set variable 
			$err_message[] = validatePasswordComplex($password); //beforn hashing check password for strengh
			$password = password_hash($password, PASSWORD_DEFAULT); // hash password variable
		
			$email = $_POST["mailadres"];
			$err_message[] = validateMail($email);
		
			$username = $_POST["username"];
			$err_message[] = validateUsername($username);
		
			$firstname = $_POST["firstname"];
			$err_message[] = validateFirstname($firstname);
		
			$lastname = $_POST["lastname"];
			$err_message[] = validateLastname($lastname);
		
			$age = $_POST["age"];
			$err_message[] = validateAge($age);
			

	#oneway of check exist	
		$data = sqlSelect ($mysqli, 'SELECT username FROM users WHERE username = ? LIMIT ?','si',$username,1);
		foreach($data as $user){
				if(isset($user['username'])){ $err_message[] = "Error: Username ( {$username} ) already taken"; }
			}
	#otherway of check exist		
		$data = sqlSelect ($mysqli, 'SELECT email FROM users WHERE email = ? LIMIT ?','si',$email,1);
		if(isset($data[0])){ $err_message[] = "Error: E-mailadres ( {$email} ) already in use"; }

		$err_message = array_filter($err_message);
		$err_message = array_values($err_message);
				
		if(!isset($err_message[0])){ 
		#create user in database.
			$stmt = $mysqli->prepare("INSERT INTO users (username,email,firstname,lastname,age,admin,password) VALUES (?, ?, ?, ?, ?, ?, ?)");
			$stmt->bind_param("sssssss", $username,$email,$firstname,$lastname,$age,$admin,$password);
			try{
				$stmt->execute();
				$stmt->close();
					}catch(Exception $stmt_excep) {
						error_log($stmt_excep->getMessage()); //error message for error log
						echo "Exception:" . $stmt_excep->getMessage();
					exit('Error code [many]'); //show user error message
					}
			
			echo "User created";
			
		unset($username);
		unset($firstname);
		unset($lastname);
		unset($age);
		unset($email);
		unset($admin);
		unset($_POST);
		unset($password);

		}else{	
			echo "<div class=\"validation\">";
			echo implode("</div><div class=\"validation\">",array_filter($err_message));
			echo "</div>";
		}
	}
?>
	<table>
		<form action="./index.php" method="POST">
				<tr><td><label for="username">Username: </td><td><input type="text" id="username" name="username" <?php if(isset($_POST["username"])){ echo "value= {$_POST["username"]}"; }; ?> placeholder="Username" pattern="^[\w\d]{1,20}$" required></label></td></tr>
				<tr><td><label for="mailadres">E-mail: </td><td><input type="text" id="mailadres" name="mailadres" <?php if(isset($_POST["mailadres"])){ echo "value= {$_POST["mailadres"]}"; }; ?> placeholder="Enter E-mailadres" required></label></td></tr>
				<tr><td><label for="password">Password: </td><td><input type="password" id="password" name="password" placeholder="Enter password" required></label></td></tr>
				<tr><td><label for="firstname">Firstname: </td><td><input type="text" id="firstname"  name="firstname" <?php if(isset($_POST["firstname"])){ echo "value= {$_POST["firstname"]}"; }; ?> placeholder="Enter firstname" pattern="^[\w\d]{1,75}$" required></label></td></tr>
				<tr><td><label for="lastname">Lastname: </td><td><input type="text" id="lastname" name="lastname"  <?php if(isset($_POST["lastname"])){ echo "value= {$_POST["lastname"]}"; }; ?>  placeholder="Enter lastname" pattern="^[\w\d]{1,75}$" required></label></td></tr>
				<tr><td><label for="age">Age: </td><td><input type="number" id="age" name="age" <?php if(isset($_POST["age"])){ echo "value= {$_POST["age"]}"; }; ?>  min="1" max="110"></label></td></tr>
				<tr><td><label for="admin">Admin: </td><td><input type="checkbox" id="admin" name="admin"></td></tr>
				<tr><td><input type="submit" value="Submit" name="submit_create"></td></tr>   
		</form>
	</table>

<?php

}

##############################################
############## Update ########################
##############################################

#######################################
#Select user list --------------------#
#######################################
if(isset($_POST['Update']) OR isset($_POST['actionUpdate']) OR isset($_POST['user_select'])){

	$users = sqlSelect($mysqli,'SELECT id,username FROM users WHERE id > ?','i','1');

	?>

	<form method="POST">
		<input type="hidden" name="actionUpdate">
		<select onchange="this.form.submit()" name="user_select">
		<option value="NULL"></option>
			<?php
				foreach($users as $user) {    
					echo "<option value=" . $user["id"] . " name=\"user_select\">" . $user['username'] . "</option>";
				}
			?>
	</select>
	</form>

	<?php
	
	#-------------------------------------#
	#End Select user ---------------------#
	#-------------------------------------#

	#######################################
	#Show info selected user -------------#
	#######################################
if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST["user_select"])) {

		$editUser = sqlSelect ($mysqli, 'SELECT id, username, email, firstname, lastname,age,admin FROM users WHERE id = ?', 'i',$_POST["user_select"]);
		$users = $editUser[0];
		
		if($users["admin"] == "1"){ $checked = "checked"; }else{ $checked=""; }
?>

			<form action="index.php" method="POST">    
				<table>
					<tr><td><label for="username">Username </td><td><input type="text" name="username" value=<?= "{$users['username']}"; ?> readonly ></label></td></tr>
					<tr><td><label for="mailadres">E-mail</td><td><input type="text" name="mailadres" value=<?= "{$users['email']}"; ?> ></label></td></tr>
					<tr><td><label for="firstname">Firstname</td><td><input type="text" name="firstname" value=<?= "{$users['firstname']}"; ?>></label></td></tr>
					<tr><td><label for="lastname">Lastname</td><td><input type="text" name="lastname" value=<?= "{$users['lastname']}"; ?> ></label></td></tr>
					<tr><td><label for="password">Password</td><td><input type="password" name="password"></label></td></tr>
					<tr><td><label for="age">Age</td><td><input type="number" name="age" min="1" max="110" value=<?= "{$users['age']}"; ?> ></label></td></tr>
					<tr><td><label for="">Admin</td><td><input type="checkbox" name="admin" <?= $checked; ?> ></label></td></tr>
					<tr><td><input type="hidden" name="id" value=<?= "{$_POST['user_select']}"; ?> >
					<input type="submit" value="Update" name="update_user">
				</table>
			</form>
<?php
	}
}
	#-------------------------------------#
	#End show info user ------------------#
	#-------------------------------------#


	#######################################
	#Update user -------------------------#
	#######################################
if ($_SERVER["REQUEST_METHOD"] === "POST" && isset($_POST["update_user"])) {

				$admin = (!isset($_POST['admin'])) ? 0 : 1;
				
				$password = $_POST["password"]; //set variable 
				$err_message[] = validatePasswordComplex($password); //beforn hashing check password for strengh
				$password = password_hash($password, PASSWORD_DEFAULT); // hash password variable

				$email = $_POST['mailadres'];
				$err_message[] = validateMail($email);

				$username = $_POST['username'];
				$err_message[] = validateUsername($username);

				$firstname = $_POST['firstname'];
				$err_message[] = validateFirstname($firstname);

				$lastname = $_POST['lastname'];
				$err_message[] = validateLastname($lastname);

				$age = $_POST['age'];
				$err_message[] = validateAge($age);

				$err_message = array_filter($err_message);
				$err_message = array_values($err_message);
				

			if(!isset($err_message[0])){
			$userupdate = sqlUpdate( $mysqli,'UPDATE users SET username = ?, email = ?, firstname = ?, lastname = ?, age = ?, admin = ?, password = ? WHERE id = ?','sssssssi',$username, $email, $firstname, $lastname, $age, $admin, $password, $_POST['id']);
				if($userupdate === TRUE ){ 
					echo "User {$username} Updated!"; 
				}else{
					echo "ERROR updating user ( {$username} )";
				}
			
			}else{ 
				echo "<div class=\"validation\">";
				echo implode("</div><div class=\"validation\">",array_filter($err_message));
				echo "</div>";
			} 
		}

##############################################
##############################################
############## Delete ########################
##############################################
##############################################

if(isset($_POST['Delete']) OR isset($_POST['user_del'])){

	if(isset($_SESSION['loggedin']) && $_SESSION['admin'] === 1) {
	
		if($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST["delete_user"])) {
			$i = 0;    
			$stmt = $mysqli->prepare("DELETE FROM users WHERE id = ?");
			$stmt->bind_param("i", $del_id);
			
			foreach ($_POST['user_del'] as $del_id) {
				if($del_id == $_SESSION['id'] ){ exit("Don't delete your own user account"); } //prevent delete own user
				 if($del_id < 3 ){ exit("Not allowed to delete account"); } //prevent delete own user
					$stmt->execute();
					$i++;
			}
				$stmt->close();
				echo " {$i} users deleted"; 
			}

		#select user
		$users = sqlSelect($mysqli,'SELECT id,username,email,admin FROM users WHERE id > ?','i','1');
		
		echo "<form method=\"POST\" action=\"index.php\">";
		echo "<table><tr><th>Select</th><th>Username</th><th>E-mail</th><th>Admin</th></tr>";
		
		foreach($users as $user) {  
			if( $user['admin'] == 1 ){ $admin = "    Admin: Yes "; }else{ $admin = ""; } 
	
				echo "<tr><label for=\"user_del\"><td>";
					echo "<input type='checkbox' name='user_del[]' value={$user['id']} > ";
				echo "</td><td>";
					echo $user['username'];
				echo "</td><td>";
					echo $user['email'];
				echo "</td><td>";
					echo $admin;
				echo "</td></label></tr>";
		}
				echo "<tr><td colspan=\"3\">";
			echo "<input type='submit' name='delete_user' value='Delete' onclick='return confirm(\"Are you sure?\")'>";
		echo "</td></tr></table>";
		echo "</form>";
		#end select user
					
		}else{
			$err_message[] = "Section refused";
		}
	}

##############################################


	}else{

?>
 <form action="<?= $_SERVER['PHP_SELF']; ?>" method="POST">
      <p><label for="username">Username:</label><input type="text" name="username" placeholder="Username" required pattern="[a-zA-Z0-9]{1,75}"></p>
      <p><label for="password">Password:</label><input type="password" name="password" placeholder="Password" required></p>
	  <p><input type="submit" value="Login" name="submit_login"></p>
 </form>

<?php

}


?>
</body>
</html>