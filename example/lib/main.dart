import 'package:example/services/stellar_service.dart';
import 'package:flutter/material.dart';
import 'package:flutter_dotenv/flutter_dotenv.dart';
import 'auth_screen.dart';
import 'model/user_model.dart';
import 'services/auth_service.dart';
import 'services/navigation_service.dart';


Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  if (AuthService.credentialManager.isSupportedPlatform) {
    await AuthService.credentialManager.init(
      preferImmediatelyAvailableCredentials: true,
    );
  }

  await dotenv.load(fileName: ".env");
  UserModel? user = await UserModel.fromPrefs();
  StellarService.sorobanServer.enableLogging = true;
  runApp(MyApp(user));
}

class MyApp extends StatelessWidget {
  final UserModel? user;
  const MyApp(this.user, {super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      debugShowCheckedModeBanner: false,
      navigatorKey: NavigationService.navigatorKey,
      home: const AuthScreen(
        key: Key('auth_screen'),
      ),
    );
  }
}
