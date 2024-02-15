<?php

function logoutUser($logout){
    if(isset($logout)) {

    session_destroy();
    unset($_SESSION);   
    return "User logged out of system";
    }
}

function sqlSelect($mysqli, $query, $types = false, ...$vars) {
$stmt = $mysqli->prepare($query);
    if($types) {
        $stmt->bind_param($types, ...$vars);
    }
    try{
        $stmt->execute();
        $resultSelect = $stmt->get_result()->fetch_all(MYSQLI_ASSOC);
        $stmt->close();
        return $resultSelect;
        
    }catch(Exception $stmt_excep) {
        error_log($stmt_excep->getMessage()); //error message for error log
       #printf("Error: %s.\n", $stmt->error);
        $stmt->close();
        return false;       
        
    }
 }
function sqlUpdate($mysqli, $query, $types = false, ...$vars) {
    $stmt = $mysqli->prepare($query);
    if($types) {
        $stmt->bind_param($types, ...$vars);
    }
    try{
        $stmt->execute(); 
        $stmt->close();
        #echo $mysqli->info;
        return true;
    }catch(Exception $stmt_excep) {
        error_log($stmt_excep->getMessage()); //error message for error log
       #printf("Error: %s.\n", $stmt->error);
        $stmt->close();
        return false;       
    }
    
}

#validate email 
function validateMail($email) {      
      if(!preg_match ('/^[_a-z0-9-+%]+(\.[_a-z0-9-]+)*@[a-z0-9-]+(\.[a-z0-9-]+)*(\.[a-z]{1,3})$/', $email)){  
        return "Error: Email is not valid.";             
    }
}

#validate username 
function validateUsername($username) {  
    if (!preg_match ('/^[\w\d]{1,50}$/', $username) ){  
        return "Error: Username is not valid.";              
    }
}

#validate firstname
function validateFirstname($firstname) {  
    if (!preg_match ('/^[\w\d]{1,50}$/', $firstname) ){  
        return "Error: Firstname is not valid. 1-75 letters. Captial allowed.";          
    }
}
#validate lastname  
function validateLastname($lastname) {  
    if (!preg_match ('/^[\w\d]{1,50}$/', $lastname) ){  
        return "Error: Lastname is not valid. 1-75 letters. Captial allowed.";              
    }
}

#validate age 
function validateAge($age){
    if (!preg_match ('/^[\d]{1,3}$/', $age) ){  
        return "Error: Age is not valid.";                        
    }
}

#validate password
function validatePasswordComplex($password){
        if (!preg_match('/^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[a-zA-Z]).{8,}$/', $password) ){
            return "Password not strong enough. ( Minmal 8 chars, 1 Upper, 1 Lower, 1 Number.";
        }
}


?>