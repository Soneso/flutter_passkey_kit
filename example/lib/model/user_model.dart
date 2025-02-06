import 'package:shared_preferences/shared_preferences.dart';

class UserModel {
  String username;
  String credentialsId;
  String contractId;

  UserModel({
    required this.username,
    required this.credentialsId,
    required this.contractId,
  });

  static Future<UserModel?> fromPrefs() async {
    UserModel? user;
    final prefs = await SharedPreferences.getInstance();
    final username = prefs.getString('sp:username');
    final contractId = prefs.getString('sp:contractId');
    final credentialsId = prefs.getString('sp:credentialsId');

    if (username != null && contractId != null && credentialsId != null) {
      user = UserModel(username: username,
          credentialsId: credentialsId,
          contractId: contractId);
    }
    return user;
  }

  Future<void> save() async {
    var prefs = await SharedPreferences.getInstance();
    prefs.setString('sp:credentialsId', credentialsId);
    prefs.setString('sp:username', username);
    prefs.setString('sp:contractId', contractId);
  }
}