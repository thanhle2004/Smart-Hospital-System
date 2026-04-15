"use client"

import * as React from "react"
import { Switch as SwitchPrimitive } from "radix-ui"

import { cn } from "@/lib/utils"

function Switch({
  className,
  size = "default",
  ...props
}: React.ComponentProps<typeof SwitchPrimitive.Root> & {
  size?: "sm" | "default"
}) {
  return (
    <SwitchPrimitive.Root
      data-slot="switch"
      data-size={size}
      className={cn(
        "peer group/switch inline-flex shrink-0 items-center rounded-full border-2 transition-all outline-none focus-visible:ring-[3px] focus-visible:ring-ring/50 disabled:cursor-not-allowed disabled:opacity-50",
        // Off state: light gray background, medium gray border
        "data-[state=unchecked]:bg-gray-200 data-[state=unchecked]:border-gray-300",
        // On state: black background, black border
        "data-[state=checked]:bg-black data-[state=checked]:border-black",
        // Size
        "data-[size=default]:h-6 data-[size=default]:w-11 data-[size=sm]:h-5 data-[size=sm]:w-9",
        className
      )}
      {...props}
    >
      <SwitchPrimitive.Thumb
        data-slot="switch-thumb"
        className={cn(
          "pointer-events-none block rounded-full bg-white shadow-lg ring-0 transition-transform",
          // Inner thumb size
          "group-data-[size=default]/switch:size-5 group-data-[size=sm]/switch:size-4",
          // Thumb movement on toggle (adjusted for border-2)
          "data-[state=checked]:translate-x-[20px] data-[state=unchecked]:translate-x-0",
          "group-data-[size=sm]/switch:data-[state=checked]:translate-x-[16px]"
        )}
      />
    </SwitchPrimitive.Root>
  )
}

export { Switch }