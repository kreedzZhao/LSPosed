/*
 * This file is part of LSPosed.
 *
 * LSPosed is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * LSPosed is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with LSPosed.  If not, see <https://www.gnu.org/licenses/>.
 *
 * Copyright (C) 2021 - 2022 LSPosed Contributors
 */

#include <sys/socket.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <sys/mman.h>

#include "zygisk.h"
#include "logging.h"
#include "loader.h"
#include "config_impl.h"
#include "magisk_loader.h"
#include "symbol_cache.h"

namespace lspd {
    int allow_unload = 0;
    int *allowUnload = &allow_unload;

    class ZygiskModule : public zygisk::ModuleBase {
        JNIEnv *env_;
        zygisk::Api *api_;

        /** 在模块加载时执行一次，用于初始化模块所需的资源或设置环境变量 */
        void onLoad(zygisk::Api *api, JNIEnv *env) override {
            env_ = env;
            api_ = api;
            MagiskLoader::Init();
            ConfigImpl::Init();
        }

        /** 在应用进程专用化之前执行，可以用于修改应用进程的环境或配置 */
        void preAppSpecialize(zygisk::AppSpecializeArgs *args) override {
            MagiskLoader::GetInstance()->OnNativeForkAndSpecializePre(
                    env_, args->uid, args->gids, args->nice_name,
                    args->is_child_zygote ? *args->is_child_zygote : false, args->app_data_dir);
        }

        /** 在应用进程专用化之后执行，用于在应用进程启动后做进一步的修改或配置 */
        void postAppSpecialize(const zygisk::AppSpecializeArgs *args) override {
            // 这里是实际初始化 hook 的地方
            MagiskLoader::GetInstance()->OnNativeForkAndSpecializePost(env_, args->nice_name, args->app_data_dir);
            if (*allowUnload) api_->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
        }

        /** 在系统服务器进程专用化之前执行，适用于对系统服务进程的环境进行早期修改 */
        void preServerSpecialize([[maybe_unused]] zygisk::ServerSpecializeArgs *args) override {
            // 通过反射保存了大量的系统关键类的信息
            MagiskLoader::GetInstance()->OnNativeForkSystemServerPre(env_);
        }

        /** 在系统服务器进程专用化之后执行，适用于在系统服务启动后进行进一步的修改 */
        void postServerSpecialize([[maybe_unused]] const zygisk::ServerSpecializeArgs *args) override {
            // 中兴手机兼容
            if (__system_property_find("ro.vendor.product.ztename")) {
                auto *process = env_->FindClass("android/os/Process");
                auto *set_argv0 = env_->GetStaticMethodID(process, "setArgV0",
                                                          "(Ljava/lang/String;)V");
                auto *name = env_->NewStringUTF("system_server");
                env_->CallStaticVoidMethod(process, set_argv0, name);
                env_->DeleteLocalRef(name);
                env_->DeleteLocalRef(process);
            }
            // 对 system_server 启动之后的进一步修改
            MagiskLoader::GetInstance()->OnNativeForkSystemServerPost(env_);
            if (*allowUnload) api_->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
        }
    };
} //namespace lspd

REGISTER_ZYGISK_MODULE(lspd::ZygiskModule);
