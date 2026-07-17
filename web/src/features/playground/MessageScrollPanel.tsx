import { Button } from "@douyinfe/semi-ui";
import { ArrowDown } from "lucide-react";
import { ReactNode, RefObject, useCallback, useEffect, useLayoutEffect, useRef, useState } from "react";
import { cx } from "../../shared/lib/className";
import { AsyncContent } from "../../shared/components/AsyncContent";
import { useAutoFollowScroll } from "./useAutoFollowScroll";

type MessageScrollPanelProps = {
  ariaLabel: string;
  children: (tailRef: RefObject<HTMLDivElement | null>) => ReactNode;
  className?: string;
  contentClassName?: string;
  enabled?: boolean;
  loading?: boolean;
  loadingPrevious?: boolean;
  onLoadPrevious?: () => void;
  preserveScrollKey?: string | number | null;
  resetKey?: string | number | null;
  scrollButtonClassName?: string;
  watch?: readonly unknown[];
};

const SCROLLBAR_VISIBLE_MS = 900;

export function MessageScrollPanel({
  ariaLabel,
  children,
  className = "",
  contentClassName = "",
  enabled = true,
  loading = false,
  loadingPrevious = false,
  onLoadPrevious,
  preserveScrollKey,
  resetKey,
  scrollButtonClassName = "",
  watch = [],
}: MessageScrollPanelProps) {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const previousHeightRef = useRef(0);
  const loadPreviousThrottleRef = useRef(false);
  const scrollbarTimerRef = useRef<number | null>(null);
  const scrollbarVisibleRef = useRef(false);
  const [scrollbarVisible, setScrollbarVisible] = useState(false);
  const scrollEnabled = enabled && !loading;

  const showScrollbar = useCallback(() => {
    if (!scrollEnabled) return;
    if (!scrollbarVisibleRef.current) {
      scrollbarVisibleRef.current = true;
      setScrollbarVisible(true);
    }
    if (scrollbarTimerRef.current !== null) window.clearTimeout(scrollbarTimerRef.current);
    scrollbarTimerRef.current = window.setTimeout(() => {
      scrollbarTimerRef.current = null;
      scrollbarVisibleRef.current = false;
      setScrollbarVisible(false);
    }, SCROLLBAR_VISIBLE_MS);
  }, [scrollEnabled]);

  useEffect(() => {
    if (!loadingPrevious) loadPreviousThrottleRef.current = false;
  }, [loadingPrevious]);

  useEffect(() => {
    const container = scrollEnabled ? containerRef.current : null;
    if (!container) return;
    container.addEventListener("scroll", showScrollbar, { passive: true });
    return () => container.removeEventListener("scroll", showScrollbar);
  }, [scrollEnabled, showScrollbar]);

  useEffect(() => {
    return () => {
      if (scrollbarTimerRef.current !== null) window.clearTimeout(scrollbarTimerRef.current);
    };
  }, []);

  useEffect(() => {
    if (scrollEnabled) return;
    if (scrollbarTimerRef.current !== null) {
      window.clearTimeout(scrollbarTimerRef.current);
      scrollbarTimerRef.current = null;
    }
    scrollbarVisibleRef.current = false;
    setScrollbarVisible(false);
  }, [scrollEnabled]);

  const onScrollToTop = useCallback(() => {
    const container = containerRef.current;
    if (!container || !onLoadPrevious || loading || loadingPrevious || loadPreviousThrottleRef.current) return;
    loadPreviousThrottleRef.current = true;
    previousHeightRef.current = container.scrollHeight;
    onLoadPrevious();
  }, [loading, loadingPrevious, onLoadPrevious]);

  const {
    following,
    tailRef,
    scrollHandlers,
    scrollToLatest,
  } = useAutoFollowScroll({
    enabled: scrollEnabled,
    containerRef,
    resetKey,
    watch,
    suspendAutoFollow: Boolean(previousHeightRef.current) || loadingPrevious,
    onScrollToTop,
  });

  useLayoutEffect(() => {
    const container = containerRef.current;
    const previousHeight = previousHeightRef.current;
    if (!container || !previousHeight) return;
    const nextScrollTop = container.scrollTop + container.scrollHeight - previousHeight;
    container.style.overflowAnchor = "none";
    container.scrollTop = nextScrollTop;
    previousHeightRef.current = 0;
    window.requestAnimationFrame(() => {
      if (containerRef.current === container) container.style.overflowAnchor = "";
    });
  }, [preserveScrollKey]);

  return (
    <div className={cx("message-scroll-shell", className)}>
      <AsyncContent
        loading={loading}
        empty={false}
        retainContentWhileLoading={false}
        wrapperClassName="message-scroll-spin"
      >
        <div
          ref={containerRef}
          className={cx("message-scroll-viewport", scrollbarVisible && "message-scroll-viewport-scrolling")}
          aria-label={ariaLabel}
          aria-busy={loading}
          tabIndex={0}
          {...scrollHandlers}
        >
          <div className={cx("message-scroll-content", contentClassName)}>
            {children(tailRef)}
          </div>
        </div>
      </AsyncContent>
      {scrollEnabled && !following ? (
        <Button
          className={cx("message-scroll-tail-floating", scrollButtonClassName)}
          icon={<ArrowDown size={16} />}
          theme="solid"
          type="tertiary"
          onClick={scrollToLatest}
          aria-label="Scroll to latest message"
        />
      ) : null}
    </div>
  );
}
