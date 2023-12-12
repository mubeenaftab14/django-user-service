from itertools import chain

from django.db.models import Q
from rest_framework import generics, status, viewsets
from rest_framework.permissions import AllowAny
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework.response import Response
from django.http import HttpResponse
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.decorators import action
from rest_framework.exceptions import ValidationError
from rest_framework import serializers as s
from django.db import transaction
import jwt
from uuid import UUID
from django.core.cache import cache
from loguru import logger
from rest_framework_simplejwt.token_blacklist.models import 
OutstandingToken
from .utils import is_valid_uuid, generateSaveOtp
from .response import ApiResponse
from . import serializers
from shared_models.models import (
    User,
    FriendRequest,
    Friend,
    Followers,
    BlockedUsers,
    Notification,
    FollowRequest,
    UserSettings,
)
from .utils import welcomeEmail, make_default_settings
from app.settings import SECRET_KEY
from rest_framework.views import APIView
from .exceptions import ApiError
from .utils import sendOtpEmail, validate_email_address
from .paginator import Pagination
from django.contrib.auth import get_user_model
from rest_framework.decorators import action
from rest_framework import viewsets
from .utils import (
    resendOTPEmail,
    createSaveResendOtp,
    forgetEmail,
    check_email_or_username,
)

from .task import (save_notification_for_public_profile,
                   save_notification_for_private_profile,
                   save_notification_for_accept_follow,
                   set_followers_and_following_cache)

from .serializers import (
    UserProfileSerializer,
    LoginCustomTokenObtainSerializer,
    LinkRefreshTokenSerializer,
    RegisterTokenObtainSerializer,
    PasswordSerializer,
    ChangePasswordSerializer,
    EmailOtpSerializer,
    FriendRequestSerializer,
    FriendSerializer,
    FriendRequestRespondSerializer,
    UserSerializer,
    FollowSerializer,
    UserSettingSerializer,
    FollowRequestRespondSerializer,
    UserDetailSerializer,
    FollowRequestSerializer,
    FollowRequestSentSerializer
)
from datetime import datetime
from django.utils import timezone




class LinkRefreshView(APIView):
    def post(self, request):
        serializer = LinkRefreshTokenSerializer(
            data=request.data, context={"request": request}
        )
        serializer.is_valid(raise_exception=True)
        return ApiResponse(
            message="access token created successfully",
            data=serializer.validated_data,
            status_code=200,
        )


class RegisterUserView(generics.ListCreateAPIView):
    serializer_class = serializers.RegisterUserSerializer
    permission_classes = [AllowAny]
    queryset = User.objects.all()

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data, 
context={'request': request})
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        headers = self.get_success_headers(serializer.data)
        return ApiResponse(
            message="An otp has sent to provided email",
            headers=headers,
            status_code=201,
        )

    def get(self, request, *args, **kwargs):
        # Return "Method Not Allowed" response for GET requests
        return self.http_method_not_allowed(request, *args, **kwargs)

class LinkCustomTokenObtainPairView(TokenObtainPairView):
    serializer_class = LoginCustomTokenObtainSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(
            data=request.data, context={"request": request}
        )
        serializer.is_valid(raise_exception=True)

        return ApiResponse(
            message="login successfully",
            data=serializer.validated_data,
            status_code=200,
        )


class OtpVerifyTokenObtainPairView(TokenObtainPairView):
    serializer_class = RegisterTokenObtainSerializer

    def patch(self, request, *args, **kwargs):
        serializer = self.get_serializer(
            data=request.data, context={"request": request}
        )
        serializer.is_valid(raise_exception=True)

        return ApiResponse(
            message="otp verified successfully",
            data=serializer.validated_data,
            status_code=200,
        )

class OptApiView(viewsets.ViewSet):
    @action(detail=False, methods=["put"])
    def resend(self, request):
        email = request.data.get("email")
        if not email:
            raise ApiError(message="email must be included", 
status_code=400)
        isEmail = check_email_or_username(email)
        try:
            if isEmail == "Email":
                user = 
get_user_model().objects.filter(email__iexact=email).first()
            if isEmail == "Username":
                user = 
get_user_model().objects.filter(username__iexact=email).first()
        except get_user_model().DoesNotExist:
            raise ApiError(message="no user with this email", 
status_code=400)
        print('okk',user)
        if user:
            otp_code = generateSaveOtp(user.email)
            data = {"user": user, "recipients": [user.email]}
            resendOTPEmail(data, otp_code)
            return ApiResponse(
                message=f"Otp resend to this username {email}", 
status_code=200
            )
        else:
            raise ApiError(message="no user with credentials", 
status_code=400)


    @action(detail=False, methods=["put"])
    def forgetPassword(self, request):
        email = request.data.get("email")

        if not email:
            raise ApiError(message="email must be included", 
status_code=400)
        isEmail = check_email_or_username(email)
        try:
            if isEmail == "Email":
                user = get_user_model().objects.get(email__iexact=email)
            if isEmail == "Username":
                user = 
get_user_model().objects.get(username__iexact=email)
        except get_user_model().DoesNotExist:
            raise ApiError(message="no user with this email", 
status_code=400)

        otp_code = generateSaveOtp(user.email)
        data = {"user": user, "recipients": [user.email]}
        forgetEmail(data, otp_code)
        return ApiResponse(
            message=f"Otp send to this username {email}", status_code=200
        )

    @action(detail=False, methods=["post"])
    def verify_otp(self, request):
        serializer = EmailOtpSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data["email"]
        isEmail = check_email_or_username(email)
        otp = serializer.validated_data["otp"]
        current_time = datetime.now(tz=timezone.utc)
        try:
            if isEmail == "Email":
                user = get_user_model().objects.get(
                    email__iexact=email, otp=otp, 
otpExpiryTime__gt=current_time
                )
            if isEmail == "Username":
                user = get_user_model().objects.get(
                    username__iexact=email, otp=otp, 
otpExpiryTime__gt=current_time
                )
            if user:
                if user.otpVerified:
                    raise ApiError(message="invalid otp", status_code=400)
                user.otpCounter = 0
                user.isVerified = True
                user.otpVerified = True
                user.save(using='default')
                return ApiResponse(
                    message=f"otp verification successfully.", 
status_code=200
                )
        except get_user_model().DoesNotExist:
            raise ApiError(message="otp invalid or expired.", 
status_code=400)

class RecreatePasswordView(APIView):
    def put(self, request):
        serializer = PasswordSerializer(data=request.data, 
context={"request": request})
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data["email"]
        password = serializer.validated_data["password"]
        otp = request.data.get("otp")

        try:
            user = get_user_model().objects.get(email__iexact=email)
            if not user.otpVerified:
                raise ApiError(message="OTP verification is pending.", 
status_code=400)
            user.otpVerified = False
            if user.otp != otp:
                raise ApiError(message="OTP mismatched", status_code=400)
            user.set_password(password)
            user.save(using='default')
        except get_user_model().DoesNotExist:
            raise ApiError(message="no user with this email", 
status_code=400)
        return ApiResponse(message=f"password has been changed.", 
status_code=200)

class logoutUser(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user_id = request.user.id
        try:
            user = get_user_model().objects.get(
                id=user_id
            )
            if user.isLogin:
                # update isLogin to False on logout
                user.isLogin = False
                user.deviceId=''
                user.deviceType= ''
                user.save(using='default')
                return ApiResponse(
                    message=f"User Logout Successfully.",
                    status_code=200,
                )
            else:
                return ApiResponse(
                    message=f"User already Logout .",
                    status_code=200,
                )
        except get_user_model().DoesNotExist:
            raise ApiError(message="User not found", status_code=400)


class emailUpdateOtp(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user_id = request.user.id
        current_time = datetime.now(tz=timezone.utc)
        serializer = EmailOtpSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data["email"]
        otp = serializer.validated_data["otp"]
        try:
            user = get_user_model().objects.get(
                id=user_id, otp=otp, otpExpiryTime__gt=current_time
            )
            if user:
                if user.otpVerified:
                    raise ApiError(message="invalid otp", status_code=400)
                if email != user.emailChangeRequest:
                    raise ApiError(
                        message="email not match, use the email on which 
you received otp",
                        status_code=400,
                    )
                user.otpCounter = 0
                user.isVerified = True
                user.otpVerified = True
                # update email
                user.email = email
                user.save(using='default')
                return ApiResponse(
                    message=f"otp verification for updating email 
successfully.",
                    status_code=200,
                )
        except get_user_model().DoesNotExist:
            raise ApiError(message="otp invalid or expired.", 
status_code=400)


class UserProfileView(viewsets.ViewSet):
    @action(detail=False, methods=["get"])
    def get_profile(self, request):
        userId = request.headers.get("userid", None)
        if userId is None:
            return Response(
                {"error": "UserId is missing from headers"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        validateUUID=is_valid_uuid(userId)
        if not validateUUID:
            return Response(
                {"error": "UserId is not a valid UUID"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            instance = User.objects.get(pk=userId)
            if not instance:
                raise ApiError(message="User object not found")
        except User.DoesNotExist:
            raise ApiError(message="User object not found", 
status_code=404)

        serializer = UserProfileSerializer(instance , 
context={"request":request,"userId":userId})
        return ApiResponse(
            message="user profile information",
            data=serializer.data,
            status_code=200,
        )

    @action(detail=False,methods=["put"])
    def change_password(self, request):
        userId = request.headers.get("userid", None)
        if userId is None:
            return Response(
                {"error": "UserId is missing from headers"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        validateUUID=is_valid_uuid(userId)
        if not validateUUID:
            return Response(
                {"error": "UserId is not a valid UUID"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        try:
            user = User.objects.get(id=userId)
        except User.DoesNotExist:
            raise ApiError(message="User object not found", 
status_code=404)
        serializer = ChangePasswordSerializer(data=request.data, 
context={"user": user})
        serializer.is_valid(raise_exception=True)
        newPassword = serializer.validated_data["newPassword"]
        user.set_password(newPassword)
        user.save(using='default')
        return ApiResponse(message=f"password has been changed.", 
status_code=200)

    @action(detail=False, methods=["put"])
    def put(self, request):
        userId = request.headers.get("userid", None)
        if userId is None:
            return Response(
                {"error": "UserId is missing from headers"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        validateUUID = is_valid_uuid(userId)
        if not validateUUID:
            return Response(
                {"error": "UserId is not a valid UUID"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        email = request.data.get("email")

        try:
            instance = User.objects.get(pk=userId)
        except User.DoesNotExist:
            return ApiError(message="User object not found.", 
status_code=404)

        serializer = UserProfileSerializer(instance, data=request.data, 
partial=True , context={"request":request})
        serializer.is_valid(raise_exception=True)
        serializer.save(using='default')
        if email:
            if email == instance.email:
                raise ApiError(
                    message="updating email should be differnt.", 
status_code=400
                )
            if User.objects.filter(email__iexact=email).exists():
                raise ApiError(
                    message="This email address is already in use.", 
status_code=400
                )
            data = {"user": instance, "recipients": [email]}
            instance.emailChangeRequest = email
            instance.save(using='default')
            sendOtpEmail(data)
            return ApiResponse(message="otp is sent to the new email", 
status_code=200)
        return ApiResponse(
            message="user profile updated successfully",
            data=serializer.data,
            status_code=200,
        )

    @action(detail=False, methods=["PUT"])
    def switch_profile(self, request):
        userId = request.headers.get("userid", None)
        if userId is None:
            return Response(
                {"error": "UserId is missing from headers"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        validateUUID = is_valid_uuid(userId)
        if not validateUUID:
            return Response(
                {"error": "UserId is not a valid UUID"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            instance = User.objects.get(pk=userId)
        except User.DoesNotExist:
            raise ApiError(message="User object not found", 
status_code=404)
        make_default_settings(user=instance)
        profileType = instance.user_settings.profileType
        if profileType == 0:
            instance.user_settings.profileType = 1
            changedTo = "public"

        if profileType == 1:
            instance.user_settings.profileType = 0
            changedTo = "private"
        instance.user_settings.save(using='default')
        instance.save(using='default')

        return ApiResponse(
            message=f"profile changed to {changedTo}",
            status_code=200,
        )

    @action(detail=False, methods=["PUT"])
    def switch_nearby(self, request):
        userId = request.headers.get("userid", None)
        if userId is None:
            return Response(
                {"error": "UserId is missing from headers"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        validateUUID = is_valid_uuid(userId)
        if not validateUUID:
            return Response(
                {"error": "UserId is not a valid UUID"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        body = request.data.get('body', request.data.get('nearby', None))
        if body is None:
            raise ApiError(message='nearby is missing in body')
        try:
            try:
                instance = User.objects.get(pk=userId)
            except User.DoesNotExist:
                raise ApiError(message="User object not found", 
status_code=400)
            make_default_settings(user=instance)
            if body == True :
                instance.user_settings.nearby = True
                changedTo = "enabled nearby"
            if body == False:
                instance.user_settings.nearby = False
                changedTo = "disabled nearby"
            instance.user_settings.save(using='default')
            instance.save(using='default')
            return ApiResponse(
                message=f"{changedTo}",
                status_code=200,
            )
        except Exception as error:
            logger.error(error)
            raise ApiError(message='Please send a valid body , valid body 
is True or False')

    @action(detail=False, methods=["DELETE"])
    def delete_profile(self, request):
        userId = request.headers.get("userid", None)
        if userId is None:
            return Response(
                {"error": "UserId is missing from headers"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        validateUUID = is_valid_uuid(userId)
        if not validateUUID:
            return Response(
                {"error": "UserId is not a valid UUID"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        try:
            instance = User.objects.get(pk=userId)
        except User.DoesNotExist:
            raise ApiError(message="User object not found", 
status_code=404)
        tokenCheck = OutstandingToken.objects.filter(user=instance.id)
        if tokenCheck:
            tokenCheck.delete()
        instance.delete()
        return ApiResponse(
            message=f"profile deleted successfully ",
            status_code=202,
        )


class UserViewSet(viewsets.ViewSet):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    serializer_class = UserSerializer
    pagination_class = Pagination
    page_size = 1

    def get_queryset(self):
        return User.objects.all().order_by('username')

    @action(detail=False, methods=["GET"])
    def userList(self, request, *args, **kwargs):
        paginator = self.pagination_class()
        page_number = int(request.query_params.get("page-number", 1))
        paginator.page_size = 
int(request.query_params.get("items-per-page", 10))
        queryset = User.objects.all().order_by('username')
        total_requests = queryset.count()
        if int(paginator.page_size) < 1:
            raise ApiError(
                message="Page size must be greater than zero.", 
status_code=400
            )

        if int(page_number) < 1:
            raise ApiError(
                message="Page no. must be greater than zero.", 
status_code=400
            )
        start_index = (int(page_number) - 1) * int(paginator.page_size)
        end_index = start_index + int(paginator.page_size)
        if start_index >= queryset.count():
            responseData = {
                "users": [],
                "metadata": {
                    "pagination":{
                        "nextPage" : False,
                        "pageNumber": int(page_number),
                        "itemsPerPage": int(paginator.page_size),
                    }
                }
            }

            return ApiResponse(
                message="users list" ,data=responseData, status_code=200
            )
        page = paginator.paginate_queryset(queryset, request)
        print(len(page))
        serializer = self.serializer_class(page, many=True, 
context={"request": request})
        nextPage = end_index < total_requests
        responseData = {
            "users": serializer.data,
            "metadata" : {
                "pagination": {
                    "nextPage" : nextPage,
                    "pageNumber": int(page_number),
                    "itemsPerPage": int(paginator.page_size),
                }
            }
        }

        return ApiResponse(
            message="users list",data=responseData, status_code=200
        )

    #  user detail
    @action(detail=False, methods=["GET"])
    def userDetail(self, request, *args, **kwargs):
        userId = self.kwargs.get("userId")
        try:
            queryset = User.objects.get(id=userId)
        except:
            raise ApiError(message="User not found", status_code=404)

        serializer = UserDetailSerializer(queryset, context={"request": 
request,"user":queryset})

        return ApiResponse(message="user detail", data=serializer.data, 
status_code=200)

    @action(detail=False, methods=["GET"])
    def publicUserList(self, request, *args, **kwargs):
        try:
            queryset = 
User.objects.filter(user_settings__profileType=1).order_by('username').values('id')
            converted_result = [item["id"] for item in queryset]
            return ApiResponse(
                message="public-users list", data=converted_result, 
status_code=200
            )
        except Exception as error:
            logger.error(error)
            return ApiError(message='something went wrong , please try 
again later')


class VerifyEmail(generics.GenericAPIView):
    """### User Verification with JWT token.
    - request: to get the token from the query parameter.
    - decode token then get user_id to change verification status.
    """

    def get(self, request):
        token = request.GET.get("token")
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms="HS256")
            user = User.objects.get(id=payload["user_id"])
            if not user.isVerified:
                user.isVerified = True
                user.save(using='default')
                data = {"user": user, "recipients": [user.email]}
                welcomeEmail(data)
            return Response("User activated", status=status.HTTP_200_OK)
        except jwt.ExpiredSignatureError:
            return ApiError(message="Activation link is expired.", 
status_code=400)
        except jwt.DecodeError:
            return Response(
                {"error": "Invalid token."}, 
status=status.HTTP_400_BAD_REQUEST
            )


REQUEST_DEFAULT_PAGE = 1
REQUEST_DEFAULT_PAGESIZE = 10


class FriendRequestViewSet(viewsets.ViewSet):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    pagination_class = Pagination
    queryset = FriendRequest.objects.all()
    serializer_class = FriendRequestSerializer

    @action(detail=False, methods=["POST"])
    def send_request(self, request, *args, **kwargs):
        from_user_uuid = request.user.id
        to_user_uuid = request.data.get("userId")
        if to_user_uuid is None:
            error = ({"userId": "userId is required in body"},)
            raise s.ValidationError(error)
        try:
            UUID(to_user_uuid)
        except ValueError:
            error = ({"userId": "Invalid input. Please provide a valid 
UUID."},)
            raise ApiError(message=error)
        if str(from_user_uuid) == str(to_user_uuid):
            raise ApiError(
                message="could not send request to your self", 
status_code=400
            )

        toUserInstance = User.objects.filter(id=to_user_uuid).first()
        make_default_settings(user=toUserInstance)
        profileType = toUserInstance.user_settings.profileType
        if profileType == 0:
            raise ApiError(
                message="User Profile is Private , You can't send him 
friend request"
            )

        fromUser_pending_request = FriendRequest.objects.filter(
            fromUser=from_user_uuid, toUser=to_user_uuid, status="pending"
        ).exists()
        toUser_pending_request = FriendRequest.objects.filter(
            fromUser=to_user_uuid, toUser=from_user_uuid, status="pending"
        ).exists()

        if fromUser_pending_request or toUser_pending_request:
            raise ApiError(message="friend request already sent", 
status_code=409)

        fromUser_accepted_request = FriendRequest.objects.filter(
            fromUser=from_user_uuid, toUser=to_user_uuid, 
status="accepted"
        ).exists()
        toUser_accepted_request = FriendRequest.objects.filter(
            fromUser=to_user_uuid, toUser=from_user_uuid, 
status="accepted"
        ).exists()

        if fromUser_accepted_request or toUser_accepted_request:
            raise ApiError(message="you are already friends", 
status_code=409)

        data = {"toUser": to_user_uuid, "fromUser": request.user.id}
        serializer = FriendRequestSerializer(data=data)
        serializer.is_valid(raise_exception=True)
        serializer.save(fromUser=request.user, toUser=toUserInstance)
        return ApiResponse(message="friend request sent", status_code=201)

    @action(detail=False, methods=["DELETE"])
    def remove(self, request, *args, **kwargs):
        serializer = FriendRequestRespondSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        friend_request_uuid = serializer.validated_data["friendRequestId"]
        try:
            friend_request = FriendRequest.objects.get(
                id=friend_request_uuid, status="pending"
            )
        except FriendRequest.DoesNotExist:
            raise ApiError(message="friend request not found", 
status_code=404)

        if request.user.id == friend_request.fromUser.id:
            friend_request.delete()
            return ApiResponse(
                message="friend request has been removed", status_code=200
            )
        raise ApiError(
            message="you are not authorized to remove the request.", 
status_code=403
        )

    @action(detail=True, methods=["POST"])
    def accept(self, request, *args, **kwargs):
        serializer = FriendRequestRespondSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        friend_request_uuid = serializer.validated_data["friendRequestId"]
        try:
            friend_request = 
FriendRequest.objects.get(id=friend_request_uuid)
        except FriendRequest.DoesNotExist:
            raise ApiError(message="friend request not found", 
status_code=404)
        if request.user.id == friend_request.toUser.id:
            if friend_request.status == "accepted":
                return ApiResponse(
                    message="friend request already accepted", 
status_code=200
                )
            if friend_request.status != "accepted":
                friend_request.status = "accepted"
                friend_request.save(using='default')
                friend_request.fromUser.friend.add(friend_request.toUser)
                friend_request.toUser.friend.add(friend_request.fromUser)
                return ApiResponse(message="friend request accepted", 
status_code=201)
        raise ApiError(
            message="you are not authorized to accept the request.", 
status_code=403
        )

    @action(detail=False, methods=["PUT"])
    def reject(self, request, *args, **kwargs):
        serializer = FriendRequestRespondSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        friend_request_uuid = serializer.validated_data["friendRequestId"]
        try:
            friend_request = 
FriendRequest.objects.get(id=friend_request_uuid)
        except FriendRequest.DoesNotExist:
            raise ApiError(message="friend request not found", 
status_code=404)
        if request.user.id == friend_request.toUser.id:
            friend_request.status = "rejected"
            friend_request.save(using='default')
            return ApiResponse(message="friend request rejected", 
status_code=200)
        raise ApiError(
            message="you are not authorized to reject the request.", 
status_code=403
        )

    @action(detail=False, methods=["GET"])
    def get_recieved_requests(self, request, *args, **kwargs):
        try:
            queryset = FriendRequest.objects.filter(
                toUser=request.user.id, status="pending"
            ).select_related("fromUser")
            paginator = self.pagination_class()
            page_number = request.query_params.get("page", 
REQUEST_DEFAULT_PAGE)
            paginator.page_size = request.query_params.get(
                "pageSize", REQUEST_DEFAULT_PAGESIZE
            )
            if int(paginator.page_size) < 1:
                raise ApiError(
                    message="Page size must be greater than zero.", 
status_code=400
                )

            if int(page_number) < 1:
                raise ApiError(
                    message="Page no. must be greater than zero.", 
status_code=400
                )
            start_index = (int(page_number) - 1) * 
int(paginator.page_size)
            end_index = start_index + int(paginator.page_size)
            if start_index >= queryset.count():
                responseData = {
                    "friendRequests": [],
                    "pagination": {
                        "count": queryset.count(),
                        "currentPage": int(page_number),
                        "pageSize": int(paginator.page_size),
                    },
                }
                return ApiResponse(
                    message="Friend Requests Recieved List",
                    data=responseData,
                    status_code=200,
                )
            results = paginator.paginate_queryset(queryset, request)
            serializer = FriendRequestSerializer(
                queryset, many=True, context={"request": request}
            )
            paginated_response = {
                "friendRequests": serializer.data,
                "pagination": {
                    "count": int(paginator.page.paginator.count),
                    "currentPage": int(paginator.page.number),
                    "pageSize": int(paginator.page_size),
                },
            }
            return ApiResponse(
                message="Friend Requests Recieved List",
                data=paginated_response,
                status_code=200,
            )
        except:
            raise ApiError(
                message="An error occurred while processing your request",
                status_code=500,
            )

    @action(detail=False, methods=["GET"])
    def get_sent_requests(self, request, *args, **kwargs):
        try:
            queryset = FriendRequest.objects.filter(
                fromUser=request.user.id, status="pending"
            )
            paginator = self.pagination_class()
            page_number = request.query_params.get("page", 
REQUEST_DEFAULT_PAGE)
            paginator.page_size = request.query_params.get(
                "pageSize", REQUEST_DEFAULT_PAGESIZE
            )
            if int(paginator.page_size) < 1:
                raise ApiError(
                    message="Page size must be greater than zero.", 
status_code=400
                )

            if int(page_number) < 1:
                raise ApiError(
                    message="Page no. must be greater than zero.", 
status_code=400
                )
            start_index = (int(page_number) - 1) * 
int(paginator.page_size)
            end_index = start_index + int(paginator.page_size)
            if start_index >= queryset.count():
                responseData = {
                    "friendRequests": [],
                    "pagination": {
                        "count": queryset.count(),
                        "currentPage": int(page_number),
                        "pageSize": int(paginator.page_size),
                    },
                }
                return ApiResponse(
                    message="Friend Requests Sent List",
                    data=responseData,
                    status_code=200,
                )
            results = paginator.paginate_queryset(queryset, request)
            serializer = FriendRequestSerializer(
                queryset, many=True, context={"request": request}
            )
            paginated_response = {
                "friendRequests": serializer.data,
                "pagination": {
                    "count": int(paginator.page.paginator.count),
                    "currentPage": int(paginator.page.number),
                    "pageSize": int(paginator.page_size),
                },
            }
            return ApiResponse(
                message="Friend Requests Sent List",
                data=paginated_response,
                status_code=200,
            )
        except:
            raise ApiError(
                message="An error occurred while processing your request",
                status_code=500,
            )


class FriendViewSet(viewsets.ViewSet):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    pagination_class = Pagination
    page_size = 1

    serializer_class = FriendSerializer

    def get_queryset(self):
        return self.request.user.friend.all()

    @action(detail=False, methods=["GET"])
    def get_friends_mutual_friends(self, request, *args, **kwargs):
        friends = self.get_queryset()
        serializer = self.serializer_class(friends, many=True)
        mutual_friends = User.objects.filter(
            Q(friend__in=friends) & Q(related_friend=self.request.user)
        ).distinct()
        serializer1 = self.serializer_class(mutual_friends, many=True)
        responseData = {"friends": serializer.data, "mutualFriends": 
serializer1.data}
        return ApiResponse(message="friends List", data=responseData, 
status_code=200)

    @action(detail=False, methods=["GET"])
    def get_friends(self, request, *args, **kwargs):
        queryset = self.get_queryset()
        paginator = self.pagination_class()
        page_number = request.query_params.get("page", 1)
        paginator.page_size = request.query_params.get("pageSize", 10)
        if int(paginator.page_size) < 1:
            raise ApiError(
                message="Page size must be greater than zero.", 
status_code=400
            )

        if int(page_number) < 1:
            raise ApiError(
                message="Page no. must be greater than zero.", 
status_code=400
            )
        start_index = (int(page_number) - 1) * int(paginator.page_size)
        end_index = start_index + int(paginator.page_size)
        if start_index >= queryset.count():
            responseData = {
                "friends": [],
                "pagination": {
                    "count": queryset.count(),
                    "currentPage": int(page_number),
                    "pageSize": int(paginator.page_size),
                },
            }
            return ApiResponse(
                message="friends List", data=responseData, status_code=200
            )

        page = paginator.paginate_queryset(queryset, request)
        serializer = self.serializer_class(page, many=True)
        responseData = {
            "friends": serializer.data,
            "pagination": {
                "count": paginator.page.paginator.count,
                "currentPage": paginator.page.number,
                "pageSize": paginator.page_size,
            },
        }
        return ApiResponse(message="friends List", data=responseData, 
status_code=200)


SEARCH_PAGE_SIZE = 10
SEARCH_PAGE_NUM = 1


class FriendSearchApiView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    serializer_class = UserSerializer
    pagination_class = Pagination

    def get(self, request):
        try:
            user = request.user
            search_param = request.query_params.get("s")
            if not search_param:
                queryset = user.related_friend.all()
            else:
                queryset = user.related_friend.filter(
                    Q(username__icontains=search_param)
                    | Q(fullName__icontains=search_param)
                    | Q(email__icontains=search_param)
                ).order_by("username", "fullName", "email")
            paginator = self.pagination_class()
            page_number = request.query_params.get("page", 
SEARCH_PAGE_NUM)
            paginator.page_size = request.query_params.get("pageSize", 
SEARCH_PAGE_SIZE)
            if int(paginator.page_size) < 1:
                raise ApiError(
                    message="Page size must be greater than zero.", 
status_code=400
                )

            if int(page_number) < 1:
                raise ApiError(
                    message="Page no. must be greater than zero.", 
status_code=400
                )
            start_index = (int(page_number) - 1) * 
int(paginator.page_size)
            end_index = start_index + int(paginator.page_size)
            if start_index >= queryset.count():
                responseData = {
                    "friends": [],
                    "pagination": {
                        "count": queryset.count(),
                        "currentPage": int(page_number),
                        "pageSize": int(paginator.page_size),
                    },
                }
                return ApiResponse(
                    message="friends search list", data=responseData, 
status_code=200
                )
            results = paginator.paginate_queryset(queryset, request)
            serializer = UserSerializer(results, many=True, 
context={"request": request})
            paginated_response = {
                "friends": serializer.data,
                "pagination": {
                    "count": int(paginator.page.paginator.count),
                    "currentPage": int(paginator.page.number),
                    "pageSize": int(paginator.page_size),
                },
            }
            return ApiResponse(
                message="Friends Search List", data=paginated_response, 
status_code=200
            )
        except Exception:
            raise ApiError(
                message="An error occurred while processing your request",
                status_code=500,
            )


class UserSearchApiView(APIView):
    serializer_class = UserSerializer
    pagination_class = Pagination

    def get(self, request):
        try:
            search_param = request.query_params.get("search")
            if not search_param:
                queryset = User.objects.all().order_by('username', 
"fullName", "email")
            else:
                if cache.get(search_param) is not None:
                    queryset = cache.get(search_param)
                else:
                    queryset = User.objects.filter(
                        Q(username__icontains=search_param)
                        | Q(fullName__icontains=search_param)
                        | Q(email__icontains=search_param)
                    ).order_by("username", "fullName", "email")
                    cache.set(search_param, queryset,timeout = 500)
            paginator = self.pagination_class()
            page_number = request.query_params.get("page-number", 
SEARCH_PAGE_NUM)
            paginator.page_size = 
request.query_params.get("items-per-page", SEARCH_PAGE_SIZE)
            total_requests = queryset.count()
            if int(paginator.page_size) < 1:
                raise ApiError(
                    message="Page size must be greater than zero.", 
status_code=400
                )

            if int(page_number) < 1:
                raise ApiError(
                    message="Page no. must be greater than zero.", 
status_code=400
                )
            start_index = (int(page_number) - 1) * 
int(paginator.page_size)
            end_index = start_index + int(paginator.page_size)
            if start_index >= queryset.count():
                responseData = {
                    "users": [],
                    "pagination": {
                        "nextPage": False,
                        "pageNumber": int(page_number),
                        "itemsPerPage": int(paginator.page_size),
                    },
                }
                return ApiResponse(
                    message="users Search list", data=responseData, 
status_code=200
                )
            results = paginator.paginate_queryset(queryset, request)
            serializer = UserSerializer(results, many=True, 
context={"request": request})
            nextPage = end_index < total_requests
            paginated_response = {
                "users": serializer.data,
                "pagination": {
                    "nextPage": nextPage,
                    "pageNumber": int(paginator.page.number),
                    "itemsPerPage": int(paginator.page_size),
                },
            }
            return ApiResponse(
                message="users Search list", data=paginated_response, 
status_code=200
            )
        except Exception as e:
            logger.error(e)
            raise ApiError(
                message="An error occurred while processing your request",
                status_code=500,
            )


class FriendRequestSearchApiView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    serializer_class = UserSerializer
    pagination_class = Pagination

    def get(self, request):
        try:
            user = request.user
            search_param = request.query_params.get("s")
            if not search_param:
                queryset = user.related_friendRequest.all()
            else:
                queryset = user.related_friendRequest.filter(
                    Q(username__icontains=search_param)
                    | Q(fullName__icontains=search_param)
                    | Q(email__icontains=search_param)
                ).order_by("username", "fullName", "email")
            paginator = self.pagination_class()
            page_number = request.query_params.get("page", 
SEARCH_PAGE_NUM)
            paginator.page_size = request.query_params.get("pageSize", 
SEARCH_PAGE_SIZE)
            if int(paginator.page_size) < 1:
                raise ApiError(
                    message="Page size must be greater than zero.", 
status_code=400
                )

            if int(page_number) < 1:
                raise ApiError(
                    message="Page no. must be greater than zero.", 
status_code=400
                )
            start_index = (int(page_number) - 1) * 
int(paginator.page_size)
            end_index = start_index + int(paginator.page_size)
            if start_index >= queryset.count():
                responseData = {
                    "friendRequests": [],
                    "pagination": {
                        "count": queryset.count(),
                        "currentPage": int(page_number),
                        "pageSize": int(paginator.page_size),
                    },
                }
                return ApiResponse(
                    message="friend requests search list",
                    data=responseData,
                    status_code=200,
                )
            results = paginator.paginate_queryset(queryset, request)
            serializer = UserSerializer(results, many=True, 
context={"request": request})
            paginated_response = {
                "friendRequests": serializer.data,
                "pagination": {
                    "count": int(paginator.page.paginator.count),
                    "currentPage": int(paginator.page.number),
                    "pageSize": int(paginator.page_size),
                },
            }
            return ApiResponse(
                message="friend requests search list",
                data=paginated_response,
                status_code=200,
            )
        except Exception:
            raise ApiError(
                message="An error occurred while processing your request",
                status_code=500,
            )


FOLLOW_DEFAULT_PAGE = 1
FOLLOW_DEFAULT_PAGESIZE = 10


class FollowViewSet(viewsets.ViewSet):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    pagination_class = Pagination
    page_size = 1
    serializer_class = UserSerializer

    @action(detail=False, methods=["POST"])
    def follow(self, request):
        serializer = FollowSerializer(data=request.data, 
context={"request": request})
        serializer.is_valid(raise_exception=True)
        toUser_uuid = serializer.validated_data["userId"]
        try:
            user_to_follow = User.objects.get(pk=toUser_uuid)
        except User.DoesNotExist:
            raise ApiError(message="User not found with such userId", 
status_code=400)
        if str(request.user.id) == str(toUser_uuid):
            raise ApiError(message="can't follow yourself", 
status_code=400)
        if Followers.objects.filter(
                follower=request.user.id, following=toUser_uuid
        ).exists():
            raise ApiError(
                message="you are already following this user", 
status_code=409
            )

        authorization_header = request.headers.get("Authorization", None)
        if authorization_header:
            auth_type, token = authorization_header.split(" ")
            if auth_type.lower() == "bearer":
                accessToken = token
        else:
            raise ApiError(
                message="Please provide an Authorization Token", 
status_code=400
            )
        make_default_settings(user=user_to_follow)
        if user_to_follow.user_settings.profileType != 0:
            request.user._state.db = 'default'
            user_to_follow._state.db = 'default'
            request.user.following.add(user_to_follow)

            
save_notification_for_public_profile.delay(senderId=request.user.id, 
receiverId=toUser_uuid,
                                                       
accessToken=accessToken)
            
set_followers_and_following_cache.delay(userId=request.user.id, 
toUserId=toUser_uuid)
            return ApiResponse(message=f"you are following 
{user_to_follow.username}")
        else:
            if FollowRequest.objects.filter(
                    fromUser=request.user, toUser=user_to_follow, 
status='pending'
            ).exists():
                raise ApiError(
                    message="Follow request already sent to this user", 
status_code=409
                )
            newRequest = FollowRequest.objects.using('default').create(
                fromUser=request.user, toUser=user_to_follow, 
status="pending"
            )
            
save_notification_for_private_profile.delay(senderId=request.user.id, 
receiverId=toUser_uuid,
                                                        
contentId=newRequest.id, accessToken=accessToken)
            return ApiResponse(
                message=f"Follow request has been sent to 
{user_to_follow.username}"
            )

    @action(detail=True, methods=["POST"])
    def accept_follow_request(self, request, *args, **kwargs):
        serializer = FollowRequestRespondSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        follow_request_uuid = serializer.validated_data["followRequestId"]
        try:
            follow_request = 
FollowRequest.objects.get(id=follow_request_uuid)
        except:
            raise ApiError(message="follow request not found", 
status_code=400)
        if str(request.user.id) == str(follow_request.toUser.id):
            if follow_request.status == "accepted":
                return ApiResponse(
                    message="follow request already accepted", 
status_code=409
                )
            if follow_request.status != "accepted":
                follow_request.status = "accepted"
                follow_request.save(using='default')
                follow_request.fromUser._state.db = 'default'
                follow_request.toUser._state.db = 'default'
                
follow_request.fromUser.following.add(follow_request.toUser)
                
set_followers_and_following_cache.delay(userId=follow_request.fromUser.id,
                                                        
toUserId=follow_request.toUser.id)
                authorization_header = 
request.headers.get("Authorization", None)
                if authorization_header:
                    auth_type, token = authorization_header.split(" ")
                    if auth_type.lower() == "bearer":
                        accessToken = token
                    else:
                        raise ApiError(
                            message="Please provide an Authorization 
Token", status_code=400
                        )
                
save_notification_for_accept_follow.delay(senderId=request.user.id,
                                                          
receiverId=follow_request.fromUser.id,
                                                          
contentId=follow_request.id, accessToken=accessToken)
                return ApiResponse(message="follow request accepted", 
status_code=201)
        raise ApiError(
            message="you are not authorized to accept the request.", 
status_code=403
        )

    @action(detail=True, methods=["DELETE"])
    def remove_follow_request(self, request, *args, **kwargs):
        serializer = FollowRequestRespondSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        follow_request_uuid = serializer.validated_data["followRequestId"]
        try:
            follow_request = 
FollowRequest.objects.get(id=follow_request_uuid)
        except FollowRequest.DoesNotExist:
            raise ApiError(message="follow request not found", 
status_code=400)
        if str(request.user.id) == str(follow_request.fromUser.id):
            follow_request.delete(using='default')
            return ApiResponse(message="follow request removed", 
status_code=202)
        raise ApiError(
            message="you are not authorized to remove the request.", 
status_code=403
        )

    @action(detail=True, methods=["PUT"])
    def reject_follow_request(self, request, *args, **kwargs):
        serializer = FollowRequestRespondSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        follow_request_uuid = serializer.validated_data["followRequestId"]
        try:
            follow_request = 
FollowRequest.objects.get(id=follow_request_uuid)
        except FollowRequest.DoesNotExist:
            raise ApiError(message="follow request not found", 
status_code=400)
        if (
                str(request.user.id) == str(follow_request.toUser.id)
                and follow_request.status != "accepted"
        ):
            follow_request.status = "rejected"
            follow_request.save(using='default')
            return ApiResponse(message="follow request reject", 
status_code=200)
        return ApiError(
            message="you are not authorized to reject the request.", 
status_code=403
        )

    @action(detail=False, methods=["DELETE"])
    def unfollow(self, request):
        serializer = FollowSerializer(data=request.data, 
context={"request": request})
        serializer.is_valid(raise_exception=True)
        toUser_uuid = serializer.validated_data["userId"]
        try:
            user_to_unfollow = User.objects.get(pk=toUser_uuid)
        except User.DoesNotExist:
            raise ApiError(message="User not found with such userId", 
status_code=400)
        if str(request.user.id) == str(toUser_uuid):
            raise ApiError(message="can't unfollow yourself", 
status_code=400)
        if Followers.objects.filter(
                follower=request.user.id, following=toUser_uuid
        ).exists():
            request.user._state.db = 'default'
            user_to_unfollow._state.db = 'default'

            request.user.following.remove(user_to_unfollow)
            
set_followers_and_following_cache.delay(userId=request.user.id, 
toUserId=user_to_unfollow.id)
            return ApiResponse(
                message=f"you have unfollowed {user_to_unfollow.username}"
            )
        else:
            raise ApiError(
                message="can't unfollow a user you're not following", 
status_code=400
            )

    @action(detail=False, methods=["GET"])
    def get_followers(self, request):
        cache_key = f'{request.user.id}-followers'
        if cache.get(cache_key) is not None:
            queryset = cache.get(cache_key)
        else:
            users_not_blocked = 
Followers.objects.filter(following=request.user, is_active=True 
).values('follower')
            queryset = 
User.objects.filter(id__in=users_not_blocked).order_by("-createdAt")
            cache.set(cache_key, queryset)

        paginator = self.pagination_class()
        page_number = request.query_params.get("page-number", 
FOLLOW_DEFAULT_PAGE)
        paginator.page_size = request.query_params.get(
            "items-per-page", FOLLOW_DEFAULT_PAGESIZE
        )
        if int(paginator.page_size) < 1:
            raise ApiError(
                message="Page size must be greater than zero.", 
status_code=400
            )

        if int(page_number) < 1:
            raise ApiError(
                message="Page no. must be greater than zero.", 
status_code=400
            )
        start_index = (int(page_number) - 1) * int(paginator.page_size)
        end_index = start_index + int(paginator.page_size)
        if start_index >= queryset.count():
            responseData = {
                "users": [],
                "metadata": {
                    "pagination": {
                        "nextPage": False,
                        "pageNumber": int(page_number),
                        "itemsPerPage": int(paginator.page_size),
                    }
                }
            }
            return ApiResponse(
                message="followers List", data=responseData, 
status_code=200
            )

        page = paginator.paginate_queryset(queryset, request)
        serializer = self.serializer_class(page, many=True, 
context={"request": request})
        nextPage = end_index < queryset.count()
        responseData = {
            "users": serializer.data,
            "metadata": {
                "pagination": {
                    "nextPage": nextPage,
                    "pageNumber": int(page_number),
                    "itemsPerPage": int(paginator.page_size),
                }
            }
        }

        return ApiResponse(
            message="list of followers", data=responseData, 
status_code=200
        )



    @action(detail=False, methods=["GET"])
    def get_followers_by_id(self, request):
        userId = request.query_params.get("user-id")
        if userId is None:
            error = ({"user-id": "required in query params"},)
            raise s.ValidationError(error)
        cache_key = f'{userId}-followers'
        if cache.get(cache_key) is not None:
            queryset = cache.get(cache_key)
        else:
            users_not_blocked = Followers.objects.filter(following=userId, 
is_active=True ).values('follower')
            queryset = 
User.objects.filter(id__in=users_not_blocked).order_by("-createdAt")
            cache.set(cache_key, queryset)

        paginator = self.pagination_class()
        page_number = request.query_params.get("page-number", 
FOLLOW_DEFAULT_PAGE)
        paginator.page_size = request.query_params.get(
            "items-per-page", FOLLOW_DEFAULT_PAGESIZE
        )
        if int(paginator.page_size) < 1:
            raise ApiError(
                message="Page size must be greater than zero.", 
status_code=400
            )

        if int(page_number) < 1:
            raise ApiError(
                message="Page no. must be greater than zero.", 
status_code=400
            )
        start_index = (int(page_number) - 1) * int(paginator.page_size)
        end_index = start_index + int(paginator.page_size)
        if start_index >= queryset.count():
            responseData = {
                "users": [],
                "metadata": {
                    "pagination": {
                        "nextPage": False,
                        "pageNumber": int(page_number),
                        "itemsPerPage": int(paginator.page_size),
                    }
                }
            }
            return ApiResponse(
                message="followers List", data=responseData, 
status_code=200
            )

        page = paginator.paginate_queryset(queryset, request)
        serializer = self.serializer_class(page, many=True, 
context={"request": request})
        nextPage = end_index < queryset.count()
        responseData = {
            "users": serializer.data,
            "metadata": {
                "pagination": {
                    "nextPage": nextPage,
                    "pageNumber": int(page_number),
                    "itemsPerPage": int(paginator.page_size),
                }
            }
        }

        return ApiResponse(
            message="list of followers", data=responseData, 
status_code=200
        )
    @action(detail=False, methods=["GET"])
    def inCircleSearch(self, request):
        search_param = request.query_params.get("search")
        if not search_param:
            raise ApiError(message='search param is required in query 
params ',status_code=400)
        following_users = 
Followers.objects.filter(Q(following__fullName__icontains=search_param) | 
Q(following__username__icontains=search_param),follower=request.user , 
is_active=True).values('following')
        follower_users = 
Followers.objects.filter(Q(follower__fullName__icontains=search_param) | 
Q(follower__username__icontains=search_param),following=request.user, 
is_active=True ).values('follower')
        combined_qs = list(chain(following_users,follower_users))
        user_ids = [entry['follower'] if 'follower' in entry else 
entry['following'] for entry in combined_qs]
        queryset = 
User.objects.filter(id__in=user_ids).order_by("-createdAt")
        paginator = self.pagination_class()
        page_number = request.query_params.get("page-number", 
FOLLOW_DEFAULT_PAGE)
        paginator.page_size = request.query_params.get(
            "items-per-page", FOLLOW_DEFAULT_PAGESIZE
        )
        if int(paginator.page_size) < 1:
            raise ApiError(
                message="Page size must be greater than zero.", 
status_code=400
            )

        if int(page_number) < 1:
            raise ApiError(
                message="Page no. must be greater than zero.", 
status_code=400
            )
        start_index = (int(page_number) - 1) * int(paginator.page_size)
        end_index = start_index + int(paginator.page_size)
        if start_index >= queryset.count():
            responseData = {
                "users": [],
                "metadata": {
                    "pagination": {
                        "nextPage": False,
                        "pageNumber": int(page_number),
                        "itemsPerPage": int(paginator.page_size),
                    }
                }
            }
            return ApiResponse(
                message="followers List", data=responseData, 
status_code=200
            )

        page = paginator.paginate_queryset(queryset, request)
        serializer = self.serializer_class(page, many=True, 
context={"request": request})
        nextPage = end_index < queryset.count()
        responseData = {
            "users": serializer.data,
            "metadata": {
                "pagination": {
                    "nextPage": nextPage,
                    "pageNumber": int(page_number),
                    "itemsPerPage": int(paginator.page_size),
                }
            }
        }

        return ApiResponse(
            message="list of followers", data=responseData, 
status_code=200
        )

    @action(detail=False, methods=["GET"])
    def get_following(self, request):
        cache_key = f'{request.user.id}-followings'
        if cache.get(cache_key) is not None:
            print("cache found not query again!!!")
            queryset = cache.get(cache_key)
        else:
            unblock_user_ids = 
Followers.objects.filter(follower=request.user, 
is_active=True).values('following')
            queryset = 
User.objects.filter(id__in=unblock_user_ids).order_by("-createdAt")
            cache.set(cache_key, queryset)

        paginator = self.pagination_class()
        page_number = request.query_params.get("page-number", 
FOLLOW_DEFAULT_PAGE)
        paginator.page_size = request.query_params.get(
            "items-per-page", FOLLOW_DEFAULT_PAGESIZE
        )
        if int(paginator.page_size) < 1:
            raise ApiError(
                message="Page size must be greater than zero.", 
status_code=400
            )

        if int(page_number) < 1:
            raise ApiError(
                message="Page no. must be greater than zero.", 
status_code=400
            )
        start_index = (int(page_number) - 1) * int(paginator.page_size)
        end_index = start_index + int(paginator.page_size)
        if start_index >= queryset.count():
            responseData = {
                "users": [],
                "metadata": {
                    "pagination": {
                        "nextPage": False,
                        "pageNumber": int(page_number),
                        "itemsPerPage": int(paginator.page_size),
                    }
                }
            }

            return ApiResponse(
                message="following List", data=responseData, 
status_code=200
            )

        page = paginator.paginate_queryset(queryset, request)
        serializer = self.serializer_class(page, many=True, 
context={"request": request})
        nextPage = end_index < queryset.count()
        responseData = {
            "users": serializer.data,
            "metadata": {
                "pagination": {
                    "nextPage": nextPage,
                    "pageNumber": int(page_number),
                    "itemsPerPage": int(paginator.page_size),
                }
            }
        }

        return ApiResponse(
            message="list of following", data=responseData, 
status_code=200
        )

    @action(detail=False, methods=["GET"])
    def get_following_by_id(self, request):
        userId = request.query_params.get("user-id")
        if userId is None:
            error = ({"user-id": "required in query params"},)
            raise s.ValidationError(error)
        cache_key = f'{userId}-followings'
        if cache.get(cache_key) is not None:
            print("cache found not query again!!!")
            queryset = cache.get(cache_key)
        else:
            unblock_user_ids = Followers.objects.filter(follower=userId, 
is_active=True).values('following')
            queryset = 
User.objects.filter(id__in=unblock_user_ids).order_by("-createdAt")
            cache.set(cache_key, queryset)

        paginator = self.pagination_class()
        page_number = request.query_params.get("page-number", 
FOLLOW_DEFAULT_PAGE)
        paginator.page_size = request.query_params.get(
            "items-per-page", FOLLOW_DEFAULT_PAGESIZE
        )
        if int(paginator.page_size) < 1:
            raise ApiError(
                message="Page size must be greater than zero.", 
status_code=400
            )

        if int(page_number) < 1:
            raise ApiError(
                message="Page no. must be greater than zero.", 
status_code=400
            )
        start_index = (int(page_number) - 1) * int(paginator.page_size)
        end_index = start_index + int(paginator.page_size)
        if start_index >= queryset.count():
            responseData = {
                "users": [],
                "metadata": {
                    "pagination": {
                        "nextPage": False,
                        "pageNumber": int(page_number),
                        "itemsPerPage": int(paginator.page_size),
                    }
                }
            }

            return ApiResponse(
                message="following List", data=responseData, 
status_code=200
            )

        page = paginator.paginate_queryset(queryset, request)
        serializer = self.serializer_class(page, many=True, 
context={"request": request})
        nextPage = end_index < queryset.count()
        responseData = {
            "users": serializer.data,
            "metadata": {
                "pagination": {
                    "nextPage": nextPage,
                    "pageNumber": int(page_number),
                    "itemsPerPage": int(paginator.page_size),
                }
            }
        }

        return ApiResponse(
            message="list of following", data=responseData, 
status_code=200
        )

    @action(detail=False, methods=["GET"])
    def get_follow_requests(self, request, *args, **kwargs):
        queryset = FollowRequest.objects.filter(
            toUser=request.user.id, status="pending"
        ).select_related("fromUser")
        total_requests = queryset.count()
        paginator = self.pagination_class()
        page_number = request.query_params.get("page-number", 
FOLLOW_DEFAULT_PAGE)
        paginator.page_size = request.query_params.get(
            "items-per-page", FOLLOW_DEFAULT_PAGESIZE
        )
        if int(paginator.page_size) < 1:
            raise ApiError(
                message="Page size must be greater than zero.", 
status_code=400
            )
        if int(page_number) < 1:
            raise ApiError(
                message="Page no. must be greater than zero.", 
status_code=400
            )
        start_index = (int(page_number) - 1) * int(paginator.page_size)
        end_index = start_index + int(paginator.page_size)
        if start_index >= total_requests:
            responseData = {
                "users": [],
                "metadata": {
                    "pagination": {
                        "nextPage": False,
                        "pageNumber": int(page_number),
                        "itemsPerPage": int(paginator.page_size),
                    }
                }
            }

            return ApiResponse(
                message="Follow Requests Received List",
                data=responseData,
                status_code=200,
            )
        results = paginator.paginate_queryset(queryset, request)
        serializer = FollowRequestSerializer(
            results, many=True, context={"request": request}
        )
        nextPage = end_index < total_requests
        responseData = {
            "users": serializer.data,
            "metadata": {
                "pagination": {
                    "nextPage": nextPage,
                    "pageNumber": int(page_number),
                    "itemsPerPage": int(paginator.page_size),
                }
            }
        }

        return ApiResponse(
            message="Follow Requests Received List",
            data=responseData,
            status_code=200,
        )

    @action(detail=False, methods=["GET"])
    def mutual_followers(self, request, *args, **kwargs):
        otherUserId = request.query_params.get("userId")
        if otherUserId is None:
            return Response(
                {"error": "UserId is missing in query params"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        userId = request.headers.get("userid", None)
        print(userId)
        if userId is None:
            return Response(
                {"error": "UserId is missing from headers"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        validateUUID = is_valid_uuid(userId)
        if not validateUUID:
            return Response(
                {"error": "UserId is not a valid UUID"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        paginator = self.pagination_class()
        page_number = request.query_params.get("page-number", 
FOLLOW_DEFAULT_PAGE)
        paginator.page_size = request.query_params.get(
            "items-per-page", FOLLOW_DEFAULT_PAGESIZE
        )
        if int(paginator.page_size) < 1:
            raise ApiError(
                message="Page size must be greater than zero.", 
status_code=400
            )

        if int(page_number) < 1:
            raise ApiError(
                message="Page no. must be greater than zero.", 
status_code=400
            )
        try:
            user1 = User.objects.get(id=userId)
        except User.DoesNotExist:
            return Response(
                {"error": "User with the provided ID does not exist."},
                status=status.HTTP_404_NOT_FOUND
            )
        try:
            user2 = User.objects.get(id=otherUserId)
        except User.DoesNotExist:
            return Response(
                {"error": "User with the provided ID does not exist."},
                status=status.HTTP_404_NOT_FOUND
            )
        user1Followers = 
user1.followers.filter(is_active=True).order_by("-createdAt")
        user2Followers = 
user2.followers.filter(is_active=True).order_by("-createdAt")
        mutual_followers = user1Followers.intersection(user2Followers)
        start_index = (int(page_number) - 1) * int(paginator.page_size)
        end_index = start_index + int(paginator.page_size)
        if start_index >= mutual_followers.count():
            responseData = {
                "users": [],
                "metadata": {
                    "pagination": {
                        "nextPage": False,
                        "pageNumber": int(page_number),
                        "itemsPerPage": int(paginator.page_size),
                    }
                }
            }

            return ApiResponse(
                message="Mutual Followers List", data=responseData, 
status_code=200
            )
        page = paginator.paginate_queryset(mutual_followers, request)
        serializer = self.serializer_class(page, many=True, 
context={"request": request})
        nextPage = end_index < mutual_followers.count()
        responseData = {
            "users": serializer.data,
            "metadata": {
                "pagination": {
                    "nextPage": nextPage,
                    "pageNumber": int(page_number),
                    "itemsPerPage": int(paginator.page_size),
                }
            }
        }

        return ApiResponse(
            message="Mutual Followers List", data=responseData, 
status_code=200
        )

    @action(detail=False, methods=["GET"])
    def get_sent_follow_requests(self, request, *args, **kwargs):
        queryset = FollowRequest.objects.filter(
            fromUser=request.user.id
        ).exclude(status='accepted').select_related("toUser")
        total_requests = queryset.count()
        paginator = self.pagination_class()
        page_number = request.query_params.get("page-number", 
FOLLOW_DEFAULT_PAGE)
        paginator.page_size = request.query_params.get(
            "items-per-page", FOLLOW_DEFAULT_PAGESIZE
        )
        if int(paginator.page_size) < 1:
            raise ApiError(
                message="Page size must be greater than zero.", 
status_code=400
            )
        if int(page_number) < 1:
            raise ApiError(
                message="Page no. must be greater than zero.", 
status_code=400
            )
        start_index = (int(page_number) - 1) * int(paginator.page_size)
        end_index = start_index + int(paginator.page_size)
        if start_index >= total_requests:
            responseData = {
                "users": [],
                "metadata": {
                    "pagination": {
                        "nextPage": False,
                        "pageNumber": int(page_number),
                        "itemsPerPage": int(paginator.page_size),
                    }
                }
            }

            return ApiResponse(
                message="Follow Requests Sent List",
                data=responseData,
                status_code=200,
            )
        results = paginator.paginate_queryset(queryset, request)
        serializer = FollowRequestSentSerializer(
            results, many=True, context={"request": request}
        )
        nextPage = end_index < total_requests
        responseData = {
            "users": serializer.data,
            "metadata": {
                "pagination": {
                    "nextPage": nextPage,
                    "pageNumber": int(page_number),
                    "itemsPerPage": int(paginator.page_size),
                }
            }
        }

        return ApiResponse(
            message="Follow Requests Sent List",
            data=responseData,
            status_code=200,
        )

    @action(detail=False, methods=["GET"])
    def get_following_ids(self, request):
        # queryset = 
request.user.following.all().order_by("username").values('id')
        unblock_users_ids = 
Followers.objects.filter(follower=request.user, 
is_active=True).values('following')
        queryset = 
User.objects.filter(id__in=unblock_users_ids).values('id')
        user_ids = list(map(lambda val: val["id"], queryset))
        return ApiResponse(
            message="following user ids", data={"users": user_ids}, 
status_code=200
        )


BLOCKUSER_DEFAULT_PAGE = 1
BLOCKUSER_DEFAULT_PAGESIZE = 10


class BlockViewSet(viewsets.ViewSet):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    pagination_class = Pagination

    @action(detail=False, methods=["POST"])
    def block(self, request):
        try:
            serializer = FollowSerializer(
                data=request.data, context={"request": request}
            )
            serializer.is_valid(raise_exception=True)
            toUser_uuid = serializer.validated_data["userId"]

            user_to_block = User.objects.get(pk=toUser_uuid)
            if str(request.user.id) == str(toUser_uuid):
                raise ApiError(message="can't Block yourself", 
status_code=400)
            if BlockedUsers.objects.filter(
                blockedBy=request.user.id, blockedUser=toUser_uuid
            ).exists():
                raise ApiError(
                    message="you are already Blocked this user", 
status_code=409
                )
            request.user._state.db = 'default'
            user_to_block._state.db = 'default'
            request.user.blockUsers.add(user_to_block)
            if Followers.objects.filter(
                follower=request.user.id, following=toUser_uuid
            ).exists():
                Followers.objects.filter(
                follower=request.user.id, 
following=toUser_uuid).update(is_active=False)
            if Followers.objects.filter(
                follower=toUser_uuid, following=request.user.id
            ).exists():
                Followers.objects.filter(
                follower=toUser_uuid, 
following=request.user.id).update(is_active=False)

            
set_followers_and_following_cache.delay(userId=request.user.id, 
toUserId=toUser_uuid)

            return ApiResponse(message=f"you have Blocked 
{user_to_block.username}")
        except User.DoesNotExist:
            raise ApiError(message="User not found with such userId", 
status_code=400)

    @action(detail=False, methods=["DELETE"])
    def unblock(self, request):
        try:
            serializer = FollowSerializer(
                data=request.data, context={"request": request}
            )
            serializer.is_valid(raise_exception=True)
            toUser_uuid = serializer.validated_data["userId"]
            user_to_unblock = User.objects.get(pk=toUser_uuid)
            if str(request.user.id) == str(toUser_uuid):
                raise ApiError(message="can't unblocked yourself", 
status_code=409)
            if BlockedUsers.objects.filter(
                blockedBy=request.user.id, blockedUser=toUser_uuid
            ).exists():
                request.user._state.db = 'default'
                user_to_unblock._state.db = 'default'
                request.user.blockUsers.remove(user_to_unblock)
                if Followers.objects.filter(
                    follower=request.user.id, following=toUser_uuid
                ).exists():
                    Followers.objects.filter(
                    follower=request.user.id, 
following=toUser_uuid).using('default').update(is_active=True)
                if Followers.objects.filter(
                    follower=toUser_uuid, following=request.user.id
                ).exists():
                    Followers.objects.filter(
                    follower=toUser_uuid, 
following=request.user.id).using('default').update(is_active=True)
                
set_followers_and_following_cache.delay(userId=request.user.id, 
toUserId=toUser_uuid)
                return ApiResponse(
                    message=f"you have unblocked 
{user_to_unblock.username}"
                )
            raise ApiError(
                message="can't unblocked user you have not blocked", 
status_code=400
            )
        except User.DoesNotExist:
            raise ApiError(message="User not found with such userId", 
status_code=400)

    @action(detail=False, methods=["GET"])
    def get_blocked_users(self, request):
        queryset = request.user.blockUsers.all().order_by("username")
        serializer = UserSerializer(queryset, many=True, 
context={"request": request})
        paginator = self.pagination_class()
        page_number = request.query_params.get("page-number", 
BLOCKUSER_DEFAULT_PAGE)
        paginator.page_size = request.query_params.get(
            "items-per-page", BLOCKUSER_DEFAULT_PAGESIZE
        )
        if int(paginator.page_size) < 1:
            raise ApiError(
                message="Page size must be greater than zero.", 
status_code=400
            )

        if int(page_number) < 1:
            raise ApiError(
                message="Page no. must be greater than zero.", 
status_code=400
            )
        start_index = (int(page_number) - 1) * int(paginator.page_size)
        end_index = start_index + int(paginator.page_size)
        if start_index >= queryset.count():
            responseData = {
                "users": [],
                "metadata" : {
                "pagination":{
                        "nextPage" : False,
                        "pageNumber": int(page_number),
                        "itemsPerPage": int(paginator.page_size),
                    }
            }
            }

            return ApiResponse(
                message="Block Users List" ,data=responseData, 
status_code=200
            )
        results = paginator.paginate_queryset(queryset, request)
        serializer = UserSerializer(results, many=True, 
context={"request": request})
        nextPage = end_index < queryset.count()
        paginated_response = {
            "users": serializer.data,
            "metadata" : {
             "pagination":{
                        "nextPage" : nextPage,
                        "pageNumber": int(page_number),
                        "itemsPerPage": int(paginator.page_size),
                }
        }
        }


        return ApiResponse(
            message="Block Users List",  data=paginated_response, 
status_code=200
        )

class UserDataAPIView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    def post(self, request):
        user_ids = request.data.get('ids', [])
        try:
            users = User.objects.filter(id__in=user_ids)
            serialized_data = UserSerializer(users, many=True, 
context={"request": request}).data
            return ApiResponse(message="user's data 
fetched",data=serialized_data)
        except Exception as error:
            logger.error(error)
            raise ApiError(message='something went wrong')


class UserSettingsViewSet(viewsets.ViewSet):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    @action(detail=False, methods=["GET"])
    def setting_get(self, request):
        try:
            is_settings_exists = 
UserSettings.objects.filter(user=request.user.id).exists()
            if not is_settings_exists:
                serializer = UserSettingSerializer(
                data=request.data, context={"request": request}
                )
                serializer.is_valid(raise_exception=True)
                serializer.save(user=request.user)
                return ApiResponse(
                    message="user settings", 
data={"settings":serializer.data}
                )
            settings_instance = UserSettings.objects.filter(
                user=request.user.id
            ).first()
            serializer = UserSettingSerializer(settings_instance)
            return ApiResponse(message="user settings", 
data={"settings":serializer.data})
        except Exception as error:
            logger.error(error)
            raise ApiError(
                message="An error occurred while processing your request",
                status_code=500,
            )

    @action(detail=False, methods=["PUT"])
    def setting_put(self, request):
        value_modifier = {
            True: True,
            False: False,
            "public": 1,
            "private": 0
        }
        nearby = request.data.get('nearby', None)
        if nearby is not None:
            if nearby not in [True, False]:
                raise ApiError(message="nearby can only have true/false 
value", status_code=400)
            else:
                request.data['nearby'] = value_modifier[nearby]
        profile_type = request.data.get('profileType', None)
        if profile_type is not None:
            if profile_type not in ['public', 'private']:
                raise ApiError(message="profileType can only have 
public/private value", status_code=400)
            else:
                request.data['profileType'] = value_modifier[profile_type]

        settings_instance = UserSettings.objects.filter(
            user=request.user.id
        ).first()
        settings_instance._state.db = 'default'
        if settings_instance:
            serializer = UserSettingSerializer(
                instance=settings_instance,
                data=request.data,
                partial=True,
                context={"request": request},
            )
            if serializer.is_valid(raise_exception=True):
                serializer.save(using='default')
                return ApiResponse(
                    message="user settings updated", 
data={"settings":serializer.data}
                )
        serializer = UserSettingSerializer(
            data=request.data, context={"request": request}
        )
        serializer.is_valid(raise_exception=True)
        serializer.save(user=request.user)
        return ApiResponse(
            message="user settings updated", 
data={"settings":serializer.data}
        )

class HealthApi(APIView):
    def get(self,request):
        response = HttpResponse(status=200)
        return response

