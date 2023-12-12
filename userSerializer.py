from datetime import datetime

from django.contrib.auth.password_validation import validate_password
from django.contrib.auth.hashers import check_password
from django.core.validators import RegexValidator
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken
from rest_framework import serializers, status
from rest_framework.validators import UniqueValidator
from shared_models.models import User, FriendRequest
from .utils import sendOtpEmail, getZodiacByDate, make_default_settings
from rest_framework.response import Response
from uuid import UUID
from .exceptions import ApiError
from shared_models.utils import validate_date_format
from shared_models.models import Notification, Followers, FollowRequest, 
BlockedUsers, UserSettings
import requests
from datetime import datetime
from django.utils import timezone
from .authentication import EmailOrUsernameModelBackend
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken
from datetime import timedelta
import jwt
import json
from loguru import logger
from env.config import Settings
from .utils import check_email_or_username, make_default_settings, 
messaging_private_rooms_api
from django.db.models import Count

settings= Settings()




class LinkRefreshTokenSerializer(serializers.Serializer):
    refreshToken = serializers.CharField(required=True)

    def validate(self, attrs):
        refresh_token = attrs.get("refreshToken")

        try:
            payload = jwt.decode(
                refresh_token, settings.SECRET_KEY, algorithms=["HS256"]
            )
            user_id = payload["user_id"]
            user = User.objects.get(id=user_id)
        except jwt.ExpiredSignatureError:
            raise ApiError(message="provided token is expired", 
status_code=400)
        except jwt.InvalidTokenError:
            raise ApiError(message="provided token is invalid", 
status_code=400)
        except User.DoesNotExist:
            raise ApiError(message=" user with this id doesn't exist ", 
status_code=400)

        access = AccessToken.for_user(user)
        access.set_exp(lifetime=timedelta(days=30))
        return {
            "token": {
                "accessToken": str(access),
            }
        }




class RegisterUserSerializer(serializers.ModelSerializer):
    """### Register User Serializer.
    - create(): Create user
    """

    email = serializers.EmailField(
        validators=[UniqueValidator(queryset=User.objects.all())]
    )
    phone = serializers.CharField(
        required=True, 
validators=[UniqueValidator(queryset=User.objects.all()),
                RegexValidator(
                regex=r"^\+[0-9]+$",
                message="Invalid phone number format. It should start with 
'+' and contain only digits.",
            ),]
    )
    password = serializers.CharField(
        write_only=True, required=True, validators=[validate_password]
    )
    gender = serializers.IntegerField(required=True)
    dateOfBirth = serializers.CharField(
        required=True, validators=[validate_date_format]
    )
    deviceId = serializers.CharField(required=True)
    deviceType = serializers.CharField(required=True)
    osVersion = serializers.CharField(required=True)

    def validate_deviceType(self, value):
        if len(value) > 7 or value not in ["Android", "IOS"]:
            raise serializers.ValidationError(
                "Only 'Android' or 'IOS' are allowed for this field"
            )
        return value

    def validate_gender(self, value):
        if value is None or value not in [0, 1, 2]:
            raise serializers.ValidationError(
                "Invalid gender value. Allowed values: 0, 1, 2"
            )
        return value

    def validate_date_format(value):
        try:
            datetime.strptime(value, '%d-%m-%Y')
        except ValueError:
            raise serializers.ValidationError("Invalid date format")

    def validate_dateOfBirth(self, value):
        date_obj = datetime.strptime(value, '%d-%m-%Y').date()
        if date_obj >= datetime.now().date():
            raise serializers.ValidationError(
                "Invalid date of Birth"
            )
        return value

    def validate(self, attrs):
        confirmPassword = 
self.context["request"].data.get("confirmPassword")
        if attrs["password"] != confirmPassword:
            raise serializers.ValidationError(
                {"password": "Password fields didn't match"}
            )
        flag = self.context['request'].query_params.get('flag')

        if flag == 'ai':
            attrs['isVerified'] = True
            attrs['otpVerified'] = True
        return attrs

    class Meta:
        model = User
        fields = (
            "email",
            "username",
            "fullName",
            "password",
            "dateOfBirth",
            "phone",
            "gender",
            "badge",
            "deviceId",
            "deviceType",
            "osVersion",
        )

    def create(self, validated_data):
        flag = self.context['request'].query_params.get('flag')

        if flag == 'ai':
            validated_data['isVerified'] = True
            validated_data['otpVerified'] = True
        else:
            validated_data['isVerified'] = False
            validated_data['otpVerified'] = False
        new_user = User.objects.create(
            email=validated_data["email"],
            username=validated_data["username"],
            dateOfBirth=validated_data["dateOfBirth"],
            phone=validated_data["phone"],
            gender=validated_data["gender"],
            deviceId=validated_data["deviceId"],
            deviceType=validated_data["deviceType"],
            osVersion=validated_data["osVersion"],
            fullName=validated_data["fullName"],
            isVerified= validated_data["isVerified"],
            otpVerified=validated_data["otpVerified"]


        )
        new_user.set_password(validated_data["password"])
        new_user.save(using='default')
        data = {
            "request": self.context["request"],
            "user": new_user,
            "recipients": [new_user.email],
        }
        sendOtpEmail(data)
        return new_user

    def to_representation(self, instance):
        representation = super().to_representation(instance)
        return representation


class RegisterTokenObtainSerializer(serializers.Serializer):
    otp = serializers.CharField(required=True)
    email = serializers.CharField(required=True)

    def validate(self, attrs):
        otp = attrs.get("otp")
        email = attrs.get("email")
        print("username or email check", email)
        current_time = datetime.now(tz=timezone.utc)
        if email and otp:
            isEmail = check_email_or_username(email)
            try:
                if isEmail == "Email":
                    user = User.objects.get(
                        email__iexact=email, otp=otp, 
otpExpiryTime__gt=current_time
                    )
                if isEmail == "Username":
                    user = User.objects.get(
                        username__iexact=email, otp=otp, 
otpExpiryTime__gt=current_time
                    )
            except User().DoesNotExist:
                raise ApiError(message="otp invalid or expired", 
status_code=400)

            if user and not user.otpVerified:
                user.otpCounter = 0
                user.isVerified = True
                user.otpVerified = True
                user.save(using='default')
                refresh = RefreshToken.for_user(user)
                access = AccessToken.for_user(user)
                access.set_exp(lifetime=timedelta(days=30))

                messaging_private_rooms_api(access_token=str(access))

                return {
                    "user": {
                        "userId": user.id,
                        "email": user.email,
                        "username": user.username,
                        "fullName": user.fullName,
                        "phone": user.phone,
                        "dateOfBirth": user.dateOfBirth,
                        "badge": user.badge,
                        "gender": user.gender,
                        "displayPhoto": user.displayPhoto,
                        "coverPhoto": user.coverPhoto,
                        "profileType": user.user_settings.profileType,
                        "description": user.description,
                        "isVerified": user.isVerified,
                    },
                    "device": {
                        "deviceId": user.deviceId,
                        "deviceType": user.deviceType,
                        "osVersion": user.osVersion,
                    },
                    "token": {
                        "accessToken": str(access),
                        "refreshToken": str(refresh),
                    },
                }
            raise ApiError(message="otp already claimed", status_code=400)

class PasswordSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    otp = serializers.CharField(min_length=4, max_length=4, required=True)
    password = serializers.CharField(required=True, 
validators=[validate_password])
    confirmPassword = serializers.CharField(required=True)

    def validate(self, attrs):
        password = attrs.get("password")
        confirmPassword = attrs.get("confirmPassword")
        if password != confirmPassword:
            raise ApiError(message="Password fields didn't match", 
status_code=400)
        return attrs

class ChangePasswordSerializer(serializers.Serializer):
    currentPassword = serializers.CharField(required=True)
    newPassword = serializers.CharField(required=True , 
validators=[validate_password])
    confirmNewPassword = serializers.CharField(required=True)

    def validate(self, attrs):
        currentPassword = attrs.get("currentPassword")
        user = self.context.get('user')
        newPassword = attrs.get("newPassword")
        confirmNewPassword = attrs.get("confirmNewPassword")

        if currentPassword:
            if check_password(currentPassword, user.password):
                if newPassword == currentPassword:
                    raise ApiError(message="currentPassword and 
newPassword can't be same", status_code=400)
            else:
                raise ApiError(
                    message="provided currentPassword is not correct.",
                    status_code=403,
                )

        if newPassword != confirmNewPassword:
            raise ApiError(message="Password fields didn't match", 
status_code=400)
        return attrs


class EmailOtpSerializer(serializers.Serializer):
    email = serializers.CharField(required=True)
    otp = serializers.CharField(required=True)




class UserProfileSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(
        read_only=True, 
validators=[UniqueValidator(queryset=User.objects.all())]
    )
    username = serializers.CharField(
        validators=[UniqueValidator(queryset=User.objects.all())]
    )
    phone = serializers.CharField(
        
validators=[UniqueValidator(queryset=User.objects.all()),RegexValidator(
                regex=r"^\+[0-9]+$",
                message="Invalid phone number format. It should start with 
'+' and contain only digits.",
            )]
    )
    badge = serializers.IntegerField(read_only=True)
    totalPostsCount = serializers.SerializerMethodField()
    profileType= serializers.SerializerMethodField()
    nearby = serializers.SerializerMethodField()
    userFollowerCount = serializers.SerializerMethodField()
    userFollowingCount = serializers.SerializerMethodField()
    class Meta:
        model = User
        fields = (
            "id","fullName", "username", "phone", "email", 
"totalPostsCount",'displayPhotoThumbnail',
            "displayPhoto", "coverPhoto", "dateOfBirth", "gender",
            "badge", "profileType",  "description", "createdAt",
            "deviceId", "deviceType", 
"osVersion",'nearby',"userFollowerCount","userFollowingCount"
        )

    def update(self, instance, validated_data):
        display_photo = validated_data.get("displayPhoto")
        cover_photo = validated_data.get("coverPhoto")
        displayPhotoThumbnail = 
validated_data.get("displayPhotoThumbnail")


        if display_photo is not None and display_photo != "":
            instance.displayPhoto = display_photo
        if cover_photo is not None and cover_photo != "":
            instance.coverPhoto = cover_photo
        if displayPhotoThumbnail is not None and displayPhotoThumbnail != 
"":
            instance.displayPhotoThumbnail = displayPhotoThumbnail

        validated_data.pop("displayPhoto", None)
        validated_data.pop("coverPhoto", None)
        validated_data.pop("displayPhotoThumbnail", None)

        for field, value in validated_data.items():
            setattr(instance, field, value)

        instance.save(using='default')
        return instance

    def get_userFollowerCount(self,obj):
        userId = self.context.get('userId')
        follower_count = Followers.objects.filter(follower=userId, 
is_active=True).values('following').annotate(
            follower_count=Count('following')).count()
        return follower_count

    def get_userFollowingCount(self,obj):
        userId = self.context.get('userId')
        following_count = Followers.objects.filter(following=userId, 
is_active=True).values('follower').annotate(
            follower_count=Count('following')).count()
        return following_count
    def get_totalPostsCount(self, obj):
        request = self.context.get('request')
        authorization_header = request.headers.get("Authorization", None)
        userId=request.user.id
        if authorization_header:
            auth_type, token = authorization_header.split(" ")
            if auth_type.lower() == "bearer":
                accessToken = token
        else:
            raise ApiError(
                message="Please provide a Authorization Token", 
status_code=400
            )
        url = settings.POSTS_POST_COUNT_ENDPOINT
        headers = {
            'Authorization': f'Bearer {accessToken}',
            'Content-Type': 'application/json'
        }
        body = {
            'userId': f'{userId}'
        }
        data_json = json.dumps(body)
        try:
            response = requests.request("POST", url, 
headers=headers,data=data_json)
            response.raise_for_status()
            posts_data = response.json()
        except requests.exceptions.RequestException as e:
            logger.error(e)
            error = "Error: post service is down, can't fetch posts count"
            logger.error(error)
            return None
        except requests.exceptions.HTTPError as e:
            logger.error(e)
            error = f"HTTP Error: {response.status_code} - 
{response.reason}"
            logger.error(error)
            return None
        total_count = posts_data['data']["count"]
        return total_count
    def get_profileType(self, obj):
        user = obj
        return user.user_settings.profileType
    def get_nearby(self, obj):
        return obj.user_settings.nearby

class UserSerializer(serializers.ModelSerializer):
    isFollower = serializers.SerializerMethodField()
    isFollowing = serializers.SerializerMethodField()
    class Meta:
        model = User
        fields = ("id", "fullName", "username", "email", 
"displayPhoto",'displayPhotoThumbnail', "isFollower", 
"isFollowing","deviceId","deviceType")

    def get_isFollower(self, obj):
        user = self.context.get('request').user
        return Followers.objects.filter(follower=obj.id, 
following=user.id).exists()
    def get_isFollowing(self, obj):
        user = self.context.get('request').user
        return Followers.objects.filter(follower=user.id, 
following=obj.id).exists()



class UserDetailSerializer(serializers.ModelSerializer):
    isFollower = serializers.SerializerMethodField()
    isFollowing = serializers.SerializerMethodField()
    isBlocked = serializers.SerializerMethodField()
    totalPostsCount = serializers.SerializerMethodField()
    isRequestPending = serializers.SerializerMethodField()
    profileType = serializers.SerializerMethodField()
    userFollowerCount = serializers.SerializerMethodField()
    userFollowingCount = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = ("isBlocked", "isFollower", "isFollowing", 
"isRequestPending",  "id","fullName", "username", "phone", "email", 
"totalPostsCount",'displayPhotoThumbnail',
            "displayPhoto", "coverPhoto", "dateOfBirth",
            "badge", "profileType",  "description", "createdAt",
            "deviceId", "deviceType", 
"osVersion","userFollowerCount","userFollowingCount")
    def get_profileType(self, obj):
        user = self.context.get('user')
        make_default_settings(user=user)
        return user.user_settings.profileType
    def get_isBlocked(self, obj):
        user = self.context.get('request').user
        return BlockedUsers.objects.filter(blockedUser=obj.id, 
blockedBy=user.id).exists()
    def get_isFollower(self, obj):
        user = self.context.get('request').user
        return Followers.objects.filter(follower=obj.id, 
following=user.id).exists()
    def get_isFollowing(self, obj):
        user = self.context.get('request').user
        return Followers.objects.filter(follower=user.id, 
following=obj.id).exists()
    def get_isRequestPending(self, obj):
        user = self.context.get('request').user
        return FollowRequest.objects.filter(fromUser=user.id, 
toUser=obj.id, status="pending").exists()

    def get_userFollowerCount(self, obj):
        follower_count = Followers.objects.filter(follower=obj.id, 
is_active=True).values('following').annotate(follower_count=Count('following')).count()
        print('count hello',follower_count)
        return follower_count

    def get_userFollowingCount(self, obj):
        following_count = Followers.objects.filter(following=obj.id, 
is_active=True).values('follower').annotate(follower_count=Count('following')).count()
        print('count hello',following_count)
        return following_count
    def get_totalPostsCount(self, obj):
        request = self.context.get('request')
        authorization_header = request.headers.get("Authorization", None)
        userId=obj.id
        if authorization_header:
            auth_type, token = authorization_header.split(" ")
            if auth_type.lower() == "bearer":
                accessToken = token
        else:
            raise ApiError(
                message="Please provide a Authorization Token", 
status_code=400
            )
        url = settings.POSTS_POST_COUNT_ENDPOINT
        headers = {
            'Authorization': f'Bearer {accessToken}',
            'Content-Type': 'application/json'
        }

        body = {
            'userId': f'{userId}'
        }
        data_json = json.dumps(body)
        try:
            response = requests.request("POST", url, headers=headers, 
data=data_json)
            response.raise_for_status()
            posts_data = response.json()
        except requests.exceptions.RequestException as e:
            logger.error(e)
            error = "Error: post service is down, can't fetch posts count"
            logger.error(error)
            return None
        except requests.exceptions.HTTPError as e:
            logger.error(e)
            error = f"HTTP Error: {response.status_code} - 
{response.reason}"
            logger.error(error)
            return None
        total_count = posts_data['data']["count"]
        return total_count














class FriendRequestSerializer(serializers.ModelSerializer):
    fromUser = serializers.SerializerMethodField()
    toUser = serializers.SerializerMethodField()

    class Meta:
        model = FriendRequest
        fields = ("id", "status", "fromUser", "toUser")

    #
    def get_toUser(self, obj):
        to_user = obj.toUser
        if to_user is not None:
            return UserSerializer(to_user).data
        else:
            return None

    def get_fromUser(self, obj):
        return UserSerializer(obj.fromUser).data


class FollowRequestSerializer(serializers.ModelSerializer):
    followRequestId = serializers.CharField(max_length=255, source="id")
    id = serializers.SerializerMethodField()
    fullName = serializers.SerializerMethodField()
    username = serializers.SerializerMethodField()
    email = serializers.SerializerMethodField()
    displayPhoto = serializers.SerializerMethodField()

    class Meta:
        model = FollowRequest
        fields = ("followRequestId", "status", "id", "email", "fullName", 
"displayPhoto", "username")

    def get_id(self, obj):
        user_id = obj.fromUser.id
        return user_id
    def get_fullName(self, obj):
        fullname = obj.fromUser.fullName
        return fullname
    def get_username(self, obj):
        username = obj.fromUser.username
        return username
    def get_email(self, obj):
        email = obj.fromUser.email
        return email
    def get_displayPhoto(self, obj):
        displayPhoto = obj.fromUser.displayPhoto
        return displayPhoto

class FollowRequestSentSerializer(serializers.ModelSerializer):
    followRequestId = serializers.CharField(max_length=255, source="id")
    id = serializers.SerializerMethodField()
    fullName = serializers.SerializerMethodField()
    username = serializers.SerializerMethodField()
    email = serializers.SerializerMethodField()
    displayPhoto = serializers.SerializerMethodField()

    class Meta:
        model = FollowRequest
        fields = ("followRequestId", "status", "id", "email", "fullName", 
"displayPhoto", "username")

    def get_id(self, obj):
        user_id = obj.toUser.id
        return user_id
    def get_fullName(self, obj):
        fullname = obj.toUser.fullName
        return fullname
    def get_username(self, obj):
        username = obj.toUser.username
        return username
    def get_email(self, obj):
        email = obj.toUser.email
        return email
    def get_displayPhoto(self, obj):
        displayPhoto = obj.toUser.displayPhoto
        return displayPhoto

class FriendSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ("id", "fullName", "username")


class MutualFriendsSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ("id", "username", "email", "friends")


class FriendRequestRespondSerializer(serializers.Serializer):
    friendRequestId = serializers.CharField(required=True)

    def validate_friendRequestId(self, value):
        try:
            UUID(value)
        except ValueError:
            # raise ApiError(message='Invalid input. Please provide a 
valid UUID.')
            raise serializers.ValidationError(
                "Invalid input. Please provide a valid UUID."
            )
        return value

class FollowRequestRespondSerializer(serializers.Serializer):
    followRequestId = serializers.CharField(required=True)

    def validate_friendRequestId(self, value):
        try:
            UUID(value)
        except ValueError:
            # raise ApiError(message='Invalid input. Please provide a 
valid UUID.')
            raise serializers.ValidationError(
                "Invalid input. Please provide a valid UUID."
            )
        return value


class FollowSerializer(serializers.Serializer):
    fromUser = 
serializers.HiddenField(default=serializers.CurrentUserDefault())
    userId = serializers.CharField(required=True)

    def validate_userId(self, value):
        try:
            UUID(value)
        except ValueError:
            # raise ApiError(message='Invalid input. Please provide a 
valid UUID.')
            raise serializers.ValidationError(
                "Invalid input. Please provide a valid UUID."
            )
        return value


class UserSettingSerializer(serializers.ModelSerializer):

    class Meta:
        model = UserSettings
        fields = 
("emailNotification","pushNotification","dmNotification","anonymousChat","nearby","profileType")

    def to_representation(self, instance):
        representation = super().to_representation(instance)
        return representation

class LoginCustomTokenObtainSerializer(serializers.Serializer):
    usernameOrEmail = serializers.CharField(required=True)
    password = serializers.CharField(required=True)
    deviceId = serializers.CharField(required=True)
    deviceType = serializers.CharField(required=True)
    osVersion = serializers.CharField(required=True)

    def validate_deviceType(self, value):
        if len(value) > 7 or value not in ["Android", "IOS"]:
            raise serializers.ValidationError(
                "Only 'Android' or 'IOS' are allowed for this field"
            )
        return value

    def validate(self, attrs):
        usernameOrEmail = attrs.get("usernameOrEmail")
        password = attrs.get("password")

        if usernameOrEmail and password:
            user = EmailOrUsernameModelBackend.authenticate(
                self.context["request"], username=usernameOrEmail, 
password=password
            )

            if not user:
                raise ApiError(
                    message="Unable to log in with provided credentials.",
                    status_code=403,
                )

            if not user.is_active:
                raise ApiError(
                    message="Account is not active.", status_code=401, 
code=12324
                )

            if not user.isVerified:
                raise ApiError(
                    message="Account is not verified.", status_code=403, 
errorCode=12323
                )

            if "deviceId" in attrs:
                user.deviceId = attrs["deviceId"]
            if "deviceType" in attrs:
                user.deviceType = attrs["deviceType"]
            if "osVersion" in attrs:
                user.osVersion = attrs["osVersion"]
            user.isLogin=True
            user.save(using='default')
            refresh = RefreshToken.for_user(user)
            access = AccessToken.for_user(user)
            refresh.set_exp(lifetime=timedelta(days=60))
            access.set_exp(lifetime=timedelta(days=30))

            return {
                "user": {
                    "userId": user.id,
                    "email": user.email,
                    "username": user.username,
                    "fullName": user.fullName,
                    "phone": user.phone,
                    "dateOfBirth": user.dateOfBirth,
                    "badge": user.badge,
                    "gender": user.gender,
                    "displayPhoto": user.displayPhoto,
                    "coverPhoto": user.coverPhoto,
                    "profileType": user.user_settings.profileType,
                    "description": user.description,
                    "isVerified": user.isVerified,
                },
                "device": {
                    "deviceId": user.deviceId,
                    "deviceType": user.deviceType,
                    "osVersion": user.osVersion,
                },
                "token": {
                    "accessToken": str(access),
                    "refreshToken": str(refresh),
                },
            }

        else:
            raise ApiError(
                message='Must include "usernameOrEmail" and "password".',
                status_code=400,
            )

